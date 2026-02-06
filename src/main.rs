#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_net::{Ipv4Address, Ipv4Cidr, StackResources, StaticConfigV4, tcp::TcpSocket};
use embassy_stm32::{Config, bind_interrupts, eth::{self, Ethernet, GenericPhy, PacketQueue, Sma}, peripherals::{self, ETH, ETH_SMA}, rcc::{self, AHBPrescaler, APBPrescaler, HSIPrescaler, Hse, HseMode, Pll, PllDiv, PllMul, PllPreDiv, PllSource, Sysclk, VoltageScale}, rng::{self, Rng}};
use embedded_io_async::Write;
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    RNG => rng::InterruptHandler<peripherals::RNG>;
});

type EthDev = Ethernet<'static, ETH, GenericPhy<Sma<'static, ETH_SMA>>>;

/// config rcc
fn get_rcc_config() -> rcc::Config {
    let mut rcc_config = rcc::Config::default();
    // activate HSE for ethernet, but use HSI internally
    rcc_config.hse = Some(Hse {
        freq: embassy_stm32::time::Hertz(25_000_000),
        mode: HseMode::Oscillator,
    });
    rcc_config.hsi = Some(HSIPrescaler::DIV1);
    rcc_config.csi = true;
    rcc_config.pll1 = Some(Pll {
        source: PllSource::HSI,
        prediv: PllPreDiv::DIV4,
        mul: PllMul::MUL50,
        divp: Some(PllDiv::DIV2),
        divq: None,
        divr: None,
    });
    rcc_config.sys = Sysclk::PLL1_P; // 400 Mhz
    rcc_config.ahb_pre = AHBPrescaler::DIV2; // 200 Mhz
    rcc_config.apb1_pre = APBPrescaler::DIV2; // 100 Mhz
    rcc_config.apb2_pre = APBPrescaler::DIV2; // 100 Mhz
    rcc_config.apb3_pre = APBPrescaler::DIV2; // 100 Mhz
    rcc_config.apb4_pre = APBPrescaler::DIV2; // 100 Mhz
    rcc_config.voltage_scale = VoltageScale::Scale1;

    rcc_config
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, EthDev>) -> ! {
    runner.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = Config::default();
    config.rcc = get_rcc_config();
    let p = embassy_stm32::init(config);
    info!("Launching");

    let mut rng = Rng::new(p.RNG, Irqs);
    let mut seed = [0; 8];
    rng.fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    let mac_addr = [0x42, 0x34, 0x67, 0xFF, 0x69, 0x01];

    static PACKETS: StaticCell<PacketQueue<4, 4>> = StaticCell::new();

    let eth_int = p.ETH;
    let ref_clk = p.PA1;
    let mdio = p.PA2;
    let mdc = p.PC1;
    let crs = p.PA7;
    let rx_d0 = p.PC4;
    let rx_d1 = p.PC5;
    let tx_d0 = p.PB12;
    let tx_d1 = p.PB13;
    let tx_en = p.PB11;
    let sma = p.ETH_SMA;

    info!("Creating Ethernet device...");

    let device = Ethernet::new(
        PACKETS.init(PacketQueue::<4, 4>::new()),
        eth_int,
        Irqs,
        ref_clk,
        crs,
        rx_d0,
        rx_d1,
        tx_d0,
        tx_d1,
        tx_en,
        mac_addr,
        sma,
        mdio,
        mdc,
    );

    info!("Created Ethernet device...");

    //let config = embassy_net::Config::dhcpv4(Default::default());
    let config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(10, 42, 0, 10), 24),
        gateway: Some(Ipv4Address::new(10, 42, 0, 1)),
        dns_servers: Default::default(),
    });

    static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();
    let (stack, runner) =
        embassy_net::new(device, config, RESOURCES.init(StackResources::new()), seed);

    spawner.spawn(net_task(runner)).unwrap();

    stack.wait_config_up().await;

    info!("IPv4: {} {}", stack.config_v4(), stack.hardware_address());
    
    info!("Network task initialized");

    let mut rx_buffer = [0; 100000];
    let mut tx_buffer = [0; 100000];

    loop {
        let mut socket: TcpSocket<'_> = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

        socket.set_timeout(Some(embassy_time::Duration::from_secs(100)));

        // You need to start a server on the host machine, for example: `nc -l 8000`
        if let Err(e) = socket.accept(8080).await {
            defmt::warn!("accept error: {:?}", e);
            continue;
        }

        defmt::info!("Connected!");

        loop {
            let mut buf = [0u8; 1024];
            match socket.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    info!("Received: {:?}", core::str::from_utf8(&buf[..n]).unwrap());
                    if let Err(e) = socket.write_all(&buf[..n]).await {
                        defmt::warn!("write error: {:?}", e);
                        break;
                    }
                }
                Err(e) => {
                    defmt::warn!("read error: {:?}", e);
                    break;
                }
            }
        }
    }
}
