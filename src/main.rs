#![no_std]
#![no_main]

mod ksz8863_phy_drv;

use core::sync::atomic::Ordering;

use defmt::*;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::{
    Runner, Stack, StackResources,
};
use embassy_stm32::{Config, bind_interrupts};
use embassy_stm32::eth::{Ethernet, PacketQueue};
use embassy_stm32::rcc;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::peripherals;
use embassy_stm32::spi::{self, Spi};
use embassy_stm32::time::mhz;
use embassy_time::{Duration, Timer};
use panic_probe as _;
use static_cell::StaticCell;

use crate::ksz8863_phy_drv::{Ksz8863Phy, PHY_LINK_BITS};

bind_interrupts!(struct Irqs {
    ETH => embassy_stm32::eth::InterruptHandler;
});

type EthPhy = Ksz8863Phy<'static>;
type EthDriver = Ethernet<'static, peripherals::ETH, EthPhy>;

// queues for raw packets before and after processing
static PACKET_QUEUE: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
// resources to hold the sockets used by the net driver. One for DHCP, one for DNS and one for TCP
static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();


fn get_rcc_config() -> rcc::Config {
    let mut rcc_config = rcc::Config::default();
    rcc_config.hsi = Some(rcc::HSIPrescaler::DIV1); // 64 MHz
    rcc_config.hsi48 = Some(Default::default()); // needed for RNG

    // pll to multiply clock cycles
    rcc_config.pll1 = Some(rcc::Pll {
        source: rcc::PllSource::HSI,
        prediv: rcc::PllPreDiv::DIV8,   // 8 MHz
        mul: rcc::PllMul::MUL40,        // 320 MHz
        divp: Some(rcc::PllDiv::DIV2),  // 160 MHz
        divq: Some(rcc::PllDiv::DIV2),  // 160 MHz
        divr: Some(rcc::PllDiv::DIV5),  // 64 MHz
    });
    rcc_config.sys = rcc::Sysclk::PLL1_P; // cpu runs with 160 MHz
    rcc_config.mux.fdcansel = rcc::mux::Fdcansel::PLL1_Q; // can runs with 160 MHz
    rcc_config.voltage_scale = rcc::VoltageScale::Scale1; // voltage scale for max 225 MHz

    rcc_config.apb1_pre = rcc::APBPrescaler::DIV2; // APB 1-4 all run with 80 MHz due to hardware limits
    rcc_config.apb2_pre = rcc::APBPrescaler::DIV2;
    rcc_config.apb3_pre = rcc::APBPrescaler::DIV2;
    rcc_config.apb4_pre = rcc::APBPrescaler::DIV2;

    rcc_config
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, EthDriver>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn phy_led_task(
    mut led_phy1: Output<'static>,
    mut led_phy2: Output<'static>,
) -> ! {
    loop {
        let bits = PHY_LINK_BITS.load(Ordering::Relaxed);

        if (bits & (1 << 0)) != 0 {
            led_phy1.set_high();
        } else {
            led_phy1.set_low();
        }

        if (bits & (1 << 1)) != 0 {
            led_phy2.set_high();
        } else {
            led_phy2.set_low();
        }

        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy_executor::task]
async fn tcp_server_task(stack: Stack<'static>) -> ! {
    let mut rx_buffer = [0u8; 1024];
    let mut tx_buffer = [0u8; 1024];
    let mut rx_data = [0u8; 256];

    loop {
        if !stack.is_link_up() {
            Timer::after(Duration::from_millis(500)).await;
            continue;
        }

        stack.wait_config_up().await;

        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(Duration::from_secs(30)));

        match socket.accept(8889).await {
            Ok(()) => {
                info!("TCP client connected");
                let _ = socket.write(b"umbilical tcp server ready\r\n").await;

                loop {
                    match socket.read(&mut rx_data).await {
                        Ok(0) => {
                            info!("TCP client disconnected");
                            break;
                        }
                        Ok(n) => {
                            let _ = socket.write(&rx_data[..n]).await;
                        }
                        Err(err) => {
                            warn!("TCP read error: {:?}", err);
                            break;
                        }
                    }
                }

                let _ = socket.flush().await;
            }
            Err(err) => {
                warn!("TCP accept error: {:?}", err);
            }
        }

        Timer::after(Duration::from_millis(100)).await;
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = Config::default();
    config.rcc = get_rcc_config();
    let p = embassy_stm32::init(config);
    info!("Launching");

    let mut ksz_reset = Output::new(p.PB0, Level::High, Speed::Low);
    let led_phy1 = Output::new(p.PD12, Level::Low, Speed::Low);
    let led_phy2 = Output::new(p.PD13, Level::Low, Speed::Low);
    //let led_phy3 = Output::new(p.PD14, Level::Low, Speed::Low);
    //let led_hb = Output::new(p.PD15, Level::Low, Speed::Low);

    info!("Pulsing KSZ8863 reset on PB0...");
    Timer::after(Duration::from_millis(2)).await;
    ksz_reset.set_low();
    Timer::after(Duration::from_millis(10)).await;
    ksz_reset.set_high();
    Timer::after(Duration::from_millis(20)).await;
    info!("KSZ8863 reset released.");

    //let sm = Sma::new(p.ETH_SMA, p.PA2, p.PC1);
    //let phy = Ksz8863Phy::new(sm, miim::DEFAULT_PHY_ADDRS);

    let mut spi_config = spi::Config::default();
    spi_config.frequency = mhz(10); // KSZ SPI supports up to 25MHz
    let spi = Spi::new_blocking(
        p.SPI3, p.PC10, p.PC12, p.PC11, spi_config,
    );
    let cs = Output::new(p.PA15, Level::High, Speed::VeryHigh);
    let phy = Ksz8863Phy::new(spi, cs);

    let mac_addr = [0x02, 0x00, 0x00, 0x88, 0x63, 0x01];
    let eth = Ethernet::new_with_phy(
        PACKET_QUEUE.init(PacketQueue::new()),
        p.ETH,
        Irqs,
        p.PA1,
        p.PA7,
        p.PC4,
        p.PC5,
        p.PB12,
        p.PB13,
        p.PB11,
        mac_addr,
        phy,
    );

    let net_cfg = embassy_net::Config::dhcpv4(Default::default());
    let net_seed = 0x00C0_FFEE_u64;
    let (stack, runner) = embassy_net::new(
        eth,
        net_cfg,
        RESOURCES.init(StackResources::new()),
        net_seed,
    );
    spawner.must_spawn(net_task(runner));

    stack.wait_config_up().await;

    spawner.must_spawn(tcp_server_task(stack));
    spawner.must_spawn(phy_led_task(led_phy1, led_phy2));

    core::future::pending::<()>().await;
}

