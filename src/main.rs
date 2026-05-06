#![no_std]
#![no_main]
#![feature(const_cmp)]
#![feature(const_trait_impl)]

mod io_threads;
mod timesync;
mod ksz8863_phy_drv;
mod ground_tm_defs;

use core::net::SocketAddr;

use defmt::{info, warn};
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_nats::UserPwdAuthenticator;
use embassy_net::dns::DnsQueryType;
use embassy_net::tcp::TcpSocket;
use embassy_net::{Runner, Stack, StackResources};
use embassy_stm32::can::{self, CanConfigurator, RxFdBuf, TxFdBuf};
use embassy_stm32::eth::{Ethernet, PacketQueue};
use embassy_stm32::exti::{self, ExtiInput};
use embassy_stm32::gpio::{Level, Output, Pull, Speed};
use embassy_stm32::interrupt::typelevel::EXTI15_10;
use embassy_stm32::mode::Async;
use embassy_stm32::peripherals::{self, FDCAN1, FDCAN2, IWDG1, RNG};
use embassy_stm32::rcc;
use embassy_stm32::rng::{self, Rng};
use embassy_stm32::spi::{self, Spi};
use embassy_stm32::time::mhz;
use embassy_stm32::wdg::IndependentWatchdog;
use embassy_stm32::{Config, bind_interrupts};
use embassy_time::{Duration, Timer};
use panic_probe as _;
use south_common::chell::ChellDefinition;
use south_common::configs::can_config::CanPeriphConfig;
use south_common::definitions::{internal_msgs, telemetry as tm};
use south_common::gen_obdh_types;
use static_cell::StaticCell;

use crate::io_threads::Reserialize;
use crate::ksz8863_phy_drv::Ksz8863Phy;

type EthPhy = Ksz8863Phy<'static>;
type EthDriver = Ethernet<'static, peripherals::ETH, EthPhy>;

// general setup stuff
const WATCHDOG_TIMEOUT_US: u32 = 300_000;
const WATCHDOG_PETTING_INTERVAL_US: u32 = WATCHDOG_TIMEOUT_US / 2;

const NTP_TIME_SRC_UPDATE_PRIO: u8 = 10;

// Obdh types
gen_obdh_types!(Umbilical, internal_msgs, on_tm => io_threads::Reserialize);

// internal messaging channels
static COM_CHANNELS: UmbilicalComChannels =
    UmbilicalComChannels::new(2);

// Heap setup
const HEAP_KB: usize = 64;

#[global_allocator]
static ALLOCATOR: emballoc::Allocator<{ HEAP_KB * 1024 }> = emballoc::Allocator::new();
extern crate alloc;

// queues for raw packets before and after processing
static PACKET_QUEUE: StaticCell<PacketQueue<4, 4>> = StaticCell::new();
// resources to hold the sockets used by the net driver. One for DHCP, one for DNS and one for TCP
static RESOURCES: StaticCell<StackResources<3>> = StaticCell::new();

// buffer sizes for tcp data before and after processing
const TCP_RX_BUF_SIZE: usize = 1024;
static TCP_RX_BUF: StaticCell<[u8; TCP_RX_BUF_SIZE]> = StaticCell::new();

const TCP_TX_BUF_SIZE: usize = 1024;
static TCP_TX_BUF: StaticCell<[u8; TCP_TX_BUF_SIZE]> = StaticCell::new();

// NATS
static NATS_STORAGE: embassy_nats::Storage = embassy_nats::Storage::new();
const NATS_ADDR: &str = "nats.tichygames.de";

static TC_CH: embassy_nats::MsgChannel = embassy_nats::MsgChannel::new();

// Static can buffer
const C_RX_BUF_SIZE: usize = 1024;
const C_TX_BUF_SIZE: usize = 32;

static C_RX_BUF: StaticCell<RxFdBuf<C_RX_BUF_SIZE>> = StaticCell::new();
static C_TX_BUF: StaticCell<TxFdBuf<C_TX_BUF_SIZE>> = StaticCell::new();

bind_interrupts!(struct Irqs {
    ETH => embassy_stm32::eth::InterruptHandler;
    RNG => rng::InterruptHandler<RNG>;

    EXTI15_10 => exti::InterruptHandler<EXTI15_10>;

    FDCAN1_IT0 => can::IT0InterruptHandler<FDCAN1>;
    FDCAN1_IT1 => can::IT1InterruptHandler<FDCAN1>;

    FDCAN2_IT0 => can::IT0InterruptHandler<FDCAN2>;
    FDCAN2_IT1 => can::IT1InterruptHandler<FDCAN2>;
});

fn get_rcc_config() -> rcc::Config {
    let mut rcc_config = rcc::Config::default();
    rcc_config.hsi = Some(rcc::HSIPrescaler::DIV1); // 64 MHz
    rcc_config.hsi48 = Some(Default::default()); // needed for RNG

    // pll to multiply clock cycles
    rcc_config.pll1 = Some(rcc::Pll {
        source: rcc::PllSource::HSI,
        prediv: rcc::PllPreDiv::DIV8,  // 8 MHz
        mul: rcc::PllMul::MUL40,       // 320 MHz
        divp: Some(rcc::PllDiv::DIV1), // 320 MHz
        divq: Some(rcc::PllDiv::DIV1), // 320 MHz
        divr: Some(rcc::PllDiv::DIV5), // 64 MHz
    });
    rcc_config.sys = rcc::Sysclk::PLL1_P; // cpu runs with 320 MHz
    rcc_config.mux.fdcansel = rcc::mux::Fdcansel::PLL1_Q; // can runs with 320 MHz
    rcc_config.voltage_scale = rcc::VoltageScale::Scale1; // voltage scale for max 225 MHz

    rcc_config.ahb_pre = rcc::AHBPrescaler::DIV2;  // AHB runs at 160 MHz due to hardware limits
    rcc_config.apb1_pre = rcc::APBPrescaler::DIV4; // APB 1-4 all run with 80 MHz due to hardware limits
    rcc_config.apb2_pre = rcc::APBPrescaler::DIV4;
    rcc_config.apb3_pre = rcc::APBPrescaler::DIV4;
    rcc_config.apb4_pre = rcc::APBPrescaler::DIV4;

    rcc_config
}

/// Watchdog petting task
#[embassy_executor::task]
async fn petter(mut watchdog: IndependentWatchdog<'static, IWDG1>) {
    loop {
        watchdog.pet();
        Timer::after_micros(WATCHDOG_PETTING_INTERVAL_US.into()).await;
    }
}

#[embassy_executor::task]
async fn launch_detection_task(msg_channel: UmbilicalTMSender, mut launch_detection: ExtiInput<'static, Async>) {
    loop {
        launch_detection.wait_for_rising_edge().await;
        let container = UmbilicalChellUnion::new(&internal_msgs::LaunchDetected, &()).unwrap();
        msg_channel.send(container).await;
    }

}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, EthDriver>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn nats_task(mut runner: embassy_nats::Runner<'static, UserPwdAuthenticator>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
pub async fn can_receiver_task(mut can_receiver: UmbilicalCanReceiver) -> ! {
    can_receiver.run().await
}

#[embassy_executor::task]
pub async fn can_sender_task(mut can_sender: UmbilicalCanSender) -> ! {
    can_sender.run().await
}

pub async fn parse_or_resolve(
    stack: &Stack<'_>,
    s: &str,
) -> Result<SocketAddr, embassy_net::dns::Error> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(sa);
    }

    let ips = stack.dns_query(s, DnsQueryType::A).await?;
    let Some(ip) = ips.first() else {
        return Err(embassy_net::dns::Error::Failed);
    };
    Ok(SocketAddr::new((*ip).into(), 4222))
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = Config::default();
    config.rcc = get_rcc_config();
    let p = embassy_stm32::init(config);
    info!("Launching");

    // unleash independent watchdog
    let mut watchdog = IndependentWatchdog::new(p.IWDG1, WATCHDOG_TIMEOUT_US);
    watchdog.unleash();
    
    // Launch detection pin
    let launch_detection = ExtiInput::new(p.PE15, p.EXTI15, Pull::Up, Irqs);

    // Ethernet phy setup
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

    let mut spi_config = spi::Config::default();
    spi_config.frequency = mhz(10); // KSZ SPI supports up to 25MHz
    let spi = Spi::new_blocking(p.SPI3, p.PC10, p.PC12, p.PC11, spi_config);
    let cs = Output::new(p.PA15, Level::High, Speed::VeryHigh);
    let phy = Ksz8863Phy::new(spi, cs, [led_phy1, led_phy2]);

    // Generate random seed and mac.
    let mut rng = Rng::new(p.RNG, Irqs);

    let mut seed = [0; 8];
    rng.fill_bytes(&mut seed);
    let seed = u64::from_le_bytes(seed);

    let mut mac_addr = [0; 6];
    rng.fill_bytes(&mut mac_addr);
    // make sure mac addr is unicast
    mac_addr[0] &= !1;

    // Ethernet device setup
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

    let (stack, runner) =
        embassy_net::new(eth, net_cfg, RESOURCES.init(StackResources::new()), seed);
    spawner.spawn(net_task(runner).unwrap());

    // Launch watchdog task
    spawner.spawn(petter(watchdog).unwrap());

    // wait for eth connection
    stack.wait_config_up().await;

    info!("Network initialized");

    // get unix time over ntp
    let unix_us = timesync::sync_internet_time(&stack).await;
    COM_CHANNELS.set_utc_us(unix_us, NTP_TIME_SRC_UPDATE_PRIO);

    // Initizlize Nats socket
    let socket = TcpSocket::new(stack, TCP_RX_BUF.init([0; _]), TCP_TX_BUF.init([0; _]));

    // resolve addr
    let socket_addr = loop {
        match parse_or_resolve(&stack, NATS_ADDR).await {
            Ok(addr) => break addr,
            Err(e) => {
                warn!("could not resolve nats addr: {:?}, retrying...", e);
                Timer::after_secs(2).await;
            }
        }
    };

    // nats connection
    let (client, runner) =
        embassy_nats::new_with_user_pwd("nats", "nats", socket_addr, socket, &NATS_STORAGE);

    // nats tc subscription
    let mut tc_client = client.clone();
    tc_client.subscribe(
        alloc::string::String::from(internal_msgs::Telecommand.address()),
        &TC_CH
    ).await;

    spawner.spawn(nats_task(runner).unwrap());

    // can 1 configuration
    let mut can_configurator =
        CanPeriphConfig::new(CanConfigurator::new(p.FDCAN1, p.PD0, p.PD1, Irqs));

    // can 2 configuration
    // let mut can_configurator =
    //     CanPeriphConfig::new(CanConfigurator::new(p.FDCAN2, p.PB5, p.PB6, Irqs));

    can_configurator
        .add_receive_topic_range(tm::id_range())
        .unwrap();

    let can_instance = can_configurator.activate(
        C_TX_BUF.init(TxFdBuf::<C_TX_BUF_SIZE>::new()),
        C_RX_BUF.init(RxFdBuf::<C_RX_BUF_SIZE>::new()),
    );

    // Setup can sender and receiver runners
    let can_receiver = UmbilicalCanReceiver::new(
        can_instance.reader(),
        &COM_CHANNELS,
        Reserialize::new(&COM_CHANNELS, client),
    );
    let can_sender = UmbilicalCanSender::new(can_instance.writer(), &COM_CHANNELS);

    // set can standby pin to low
    let _can_1_standby = Output::new(p.PE2, Level::Low, Speed::Low);
    // let _can_2_standby = Output::new(p.PE3, Level::Low, Speed::Low);


    spawner.spawn(can_receiver_task(can_receiver).unwrap());
    spawner.spawn(can_sender_task(can_sender).unwrap());
    spawner.spawn(io_threads::telecommand_task(&COM_CHANNELS, tc_client).unwrap());
    spawner.spawn(launch_detection_task(COM_CHANNELS.get_tm_sender(), launch_detection).unwrap());

    core::future::pending::<()>().await;
}
