#![no_std]
#![no_main]

use core::convert::Infallible;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};
use core::task::Context;

use defmt::*;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{
    Config as NetConfig, Ipv4Address, Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4,
};
use embassy_stm32::bind_interrupts;
use embassy_stm32::eth::{Ethernet, PacketQueue, Phy, Sma, StationManagement};
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::peripherals;
use embassy_time::{Duration, Instant, Timer, with_timeout};
use panic_probe as _;
use static_cell::StaticCell;

bind_interrupts!(struct Irqs {
    ETH => embassy_stm32::eth::InterruptHandler;
});

type EthPhy = Ksz8863Phy<Sma<'static, peripherals::ETH_SMA>>;
type EthDriver = Ethernet<'static, peripherals::ETH, EthPhy>;

static ETH_QUEUE: StaticCell<MaybeUninit<PacketQueue<8, 8>>> = StaticCell::new();
static NET_RESOURCES: StaticCell<StackResources<8>> = StaticCell::new();
static PHY_LINK_BITS: AtomicU8 = AtomicU8::new(0);

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, EthDriver>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn status_task(stack: Stack<'static>) -> ! {
    info!("Ethernet stack started, waiting for link...");
    let mut next_wait_log = Instant::now();

    loop {
        if !stack.is_link_up() {
            if Instant::now() >= next_wait_log {
                info!("Still waiting for link...");
                next_wait_log = Instant::now() + Duration::from_secs(2);
            }
            Timer::after(Duration::from_millis(500)).await;
            continue;
        }

        info!("Link is up.");
        stack.wait_config_up().await;

        if let Some(cfg) = stack.config_v4() {
            info!("IPv4: addr={}, gateway={:?}", cfg.address, cfg.gateway);
        }

        while stack.is_link_up() {
            Timer::after(Duration::from_secs(2)).await;
        }

        warn!("Link down, waiting for reconnect...");
    }
}

#[embassy_executor::task]
async fn udp_heartbeat_task(stack: Stack<'static>, mut led_hb: Output<'static>) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; 1];
    let mut rx_buffer = [0u8; 64];
    let mut tx_meta = [PacketMetadata::EMPTY; 1];
    let mut tx_buffer = [0u8; 256];
    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );

    let _ = socket.bind(9222);

    loop {
        if !stack.is_link_up() {
            Timer::after(Duration::from_millis(500)).await;
            continue;
        }

        stack.wait_config_up().await;

        match with_timeout(
            Duration::from_millis(120),
            socket.send_to(
                b"umbilical heartbeat",
                (Ipv4Address::new(10, 42, 0, 1), 9222),
            ),
        )
        .await
        {
            Ok(Ok(())) => info!("Heartbeat sent to 10.42.0.1:9222"),
            Ok(Err(err)) => warn!("Heartbeat send failed: {:?}", err),
            Err(_) => warn!("Heartbeat send timed out"),
        }

        match with_timeout(
            Duration::from_millis(120),
            socket.send_to(
                b"umbilical heartbeat bcast",
                (Ipv4Address::new(10, 42, 0, 255), 9222),
            ),
        )
        .await
        {
            Ok(Ok(())) => info!("Heartbeat broadcast sent to 10.42.0.255:9222"),
            Ok(Err(err)) => warn!("Heartbeat broadcast failed: {:?}", err),
            Err(_) => warn!("Heartbeat broadcast timed out"),
        }

        led_hb.set_high();
        Timer::after(Duration::from_millis(60)).await;
        led_hb.set_low();

        Timer::after(Duration::from_secs(1)).await;
    }
}

#[embassy_executor::task]
async fn phy_led_task(
    mut led_phy1: Output<'static>,
    mut led_phy2: Output<'static>,
    mut led_phy3: Output<'static>,
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

        if (bits & (1 << 2)) != 0 {
            led_phy3.set_high();
        } else {
            led_phy3.set_low();
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

        info!("TCP server listening on 10.42.0.10:8889");
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

#[embassy_executor::task]
async fn udp_rx_probe_task(stack: Stack<'static>) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; 4];
    let mut rx_buffer = [0u8; 512];
    let mut tx_meta = [PacketMetadata::EMPTY; 1];
    let mut tx_buffer = [0u8; 64];
    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );

    let _ = socket.bind(5201);
    info!("UDP RX probe listening on 10.42.0.10:5201");

    let mut buf = [0u8; 256];
    loop {
        if !stack.is_link_up() {
            Timer::after(Duration::from_millis(500)).await;
            continue;
        }

        stack.wait_config_up().await;

        match with_timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
            Ok(Ok((n, meta))) => {
                info!("UDP RX probe got {} bytes from {:?}", n, meta.endpoint);
            }
            Ok(Err(err)) => warn!("UDP RX probe error: {:?}", err),
            Err(_) => {}
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    let p = embassy_stm32::init(Default::default());
    let mut ksz_reset = Output::new(p.PB0, Level::High, Speed::Low);
    let led_phy1 = Output::new(p.PD12, Level::Low, Speed::Low);
    let led_phy2 = Output::new(p.PD13, Level::Low, Speed::Low);
    let led_phy3 = Output::new(p.PD14, Level::Low, Speed::Low);
    let led_hb = Output::new(p.PD15, Level::Low, Speed::Low);

    info!("Pulsing KSZ8863 reset on PB0...");
    Timer::after(Duration::from_millis(2)).await;
    ksz_reset.set_low();
    Timer::after(Duration::from_millis(10)).await;
    ksz_reset.set_high();
    Timer::after(Duration::from_millis(20)).await;
    info!("KSZ8863 reset released.");

    let packet_queue = ETH_QUEUE.init(MaybeUninit::uninit());
    PacketQueue::init(packet_queue);
    let packet_queue = unsafe { packet_queue.assume_init_mut() };

    let sm = Sma::new(p.ETH_SMA, p.PA2, p.PC1);
    let phy = Ksz8863Phy::new(sm);

    let mac_addr = [0x02, 0x00, 0x00, 0x88, 0x63, 0x01];
    let eth = Ethernet::new_with_phy(
        packet_queue,
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

    let net_cfg = NetConfig::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Address::new(10, 42, 0, 10), 24),
        gateway: Some(Ipv4Address::new(10, 42, 0, 1)),
        dns_servers: Default::default(),
    });
    let net_seed = 0x00C0_FFEE_u64;
    let (stack, runner) = embassy_net::new(
        eth,
        net_cfg,
        NET_RESOURCES.init(StackResources::new()),
        net_seed,
    );

    unwrap!(spawner.spawn(net_task(runner)));
    unwrap!(spawner.spawn(status_task(stack)));
    unwrap!(spawner.spawn(udp_heartbeat_task(stack, led_hb)));
    unwrap!(spawner.spawn(tcp_server_task(stack)));
    unwrap!(spawner.spawn(udp_rx_probe_task(stack)));
    unwrap!(spawner.spawn(phy_led_task(led_phy1, led_phy2, led_phy3)));

    loop {
        let _ = &ksz_reset;
        Timer::after(Duration::from_secs(60)).await;
    }
}

struct Ksz8863Phy<SM: StationManagement> {
    sm: SM,
    poll_interval: Duration,
    next_poll_at: Instant,
    next_diag_at: Instant,
    cached_link: bool,
}

impl<SM: StationManagement> Ksz8863Phy<SM> {
    fn new(sm: SM) -> Self {
        Self {
            sm,
            poll_interval: Duration::from_millis(300),
            next_poll_at: Instant::from_ticks(0),
            next_diag_at: Instant::from_ticks(0),
            cached_link: false,
        }
    }

    fn with_smi<R>(&mut self, f: impl FnOnce(&mut ksz8863::Smi<KszSmi<'_, SM>>) -> R) -> R {
        let iface = KszSmi { sm: &mut self.sm };
        let mut smi_bus = ksz8863::Smi(iface);
        f(&mut smi_bus)
    }

    fn any_port_link_up(&mut self) -> bool {
        self.with_smi(|bus|{
            let phy1_link = bus.port1_status0().read().unwrap().read().link_good().bit_is_set();
            let phy2_link = bus.port1_status0().read().unwrap().read().link_good().bit_is_set();
            let phy3_link = bus.port1_status0().read().unwrap().read().link_good().bit_is_set();
            phy1_link || phy2_link || phy3_link
        })
    }

    fn diag_ports(&mut self) {
        let mut link_bits = 0u8;
        for phy_addr in 1..=3 {
            let id1 = self.sm.smi_read(phy_addr, 0x02);
            let id2 = self.sm.smi_read(phy_addr, 0x03);
            let bsr_raw = self.sm.smi_read(phy_addr, 0x01); // status register
            let bcr_raw = self.sm.smi_read(phy_addr, 0x00); // config register
            let link = (bsr_raw & (1 << 2)) != 0;
            let an_done = (bsr_raw & (1 << 5)) != 0;

            if link && (1..=3).contains(&phy_addr) {
                link_bits |= 1 << (phy_addr - 1);
            }

            info!(
                "PHY {} id1={} id2={} config={:b} status={:b} link={} an_done={}",
                phy_addr, id1, id2, bcr_raw, bsr_raw, link, an_done,
            );
        }

        PHY_LINK_BITS.store(link_bits, Ordering::Relaxed);
    }
}

impl<SM: StationManagement> Phy for Ksz8863Phy<SM> {
    fn phy_reset(&mut self) {
        self.with_smi(|bus| {
            bus.reset().modify(|m| m.software().set_bit());
        });
    }

    fn phy_init(&mut self) {
        self.with_smi(|bus| {
            bus.fwd_invalid_vid_frame_and_host_mode().write(|w| w.p3_rmii_clock_selection().set_bit()); // internally route refclk output to input (port 3 rmii)
            // bus.pwr_mgmt_and_led_mode().write(|w| w.led_mode_selection().bits(0b01)); // Link / Act
            bus.port1_ctrl12()
                .write(|w| w.an_enable().set_bit().force_speed().set_bit());
            bus.port2_ctrl12()
                .write(|w| w.an_enable().set_bit().force_speed().set_bit());
        })
    }

    fn poll_link(&mut self, cx: &mut Context) -> bool {
        let now = Instant::now();
        if now >= self.next_diag_at {
            self.diag_ports();
            self.next_diag_at = now + Duration::from_secs(2);
        }

        if now < self.next_poll_at {
            cx.waker().wake_by_ref();
            return self.cached_link;
        }

        self.cached_link = self.any_port_link_up();
        self.next_poll_at = now + self.poll_interval;
        self.cached_link
    }
}

struct KszSmi<'a, SM: StationManagement> {
    sm: &'a mut SM,
}

impl<SM: StationManagement> mdio::Read for KszSmi<'_, SM> {
    type Error = Infallible;

    fn read(&mut self, ctrl_bits: u16) -> Result<u16, Self::Error> {
        Ok(self.sm.smi_read(
            ((ctrl_bits >> 7) as u8) & 0b00011111,
            ((ctrl_bits >> 2) as u8) & 0b00011111,
        ))
    }
}

impl<SM: StationManagement> mdio::Write for KszSmi<'_, SM> {
    type Error = Infallible;

    fn write(&mut self, ctrl_bits: u16, data_bits: u16) -> Result<(), Self::Error> {
        self.sm.smi_write(
            ((ctrl_bits >> 7) as u8) & 0b00011111,
            ((ctrl_bits >> 2) as u8) & 0b00011111,
            data_bits,
        );
        Ok(())
    }
}
