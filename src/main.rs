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
use ksz8863::miim;
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
	let phy = Ksz8863Phy::new(sm, miim::DEFAULT_PHY_ADDRS);

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
	port_phys: [u8; 4],
	port_phys_count: usize,
	poll_interval: Duration,
	next_poll_at: Instant,
	next_diag_at: Instant,
	cached_link: bool,
}

impl<SM: StationManagement> Ksz8863Phy<SM> {
	fn new(sm: SM, port_phys: [u8; 2]) -> Self {
		let mut phy_addrs = [u8::MAX; 4];
		phy_addrs[0] = port_phys[0];
		phy_addrs[1] = port_phys[1];

		Self {
			sm,
			port_phys: phy_addrs,
			port_phys_count: 2,
			poll_interval: Duration::from_millis(300),
			next_poll_at: Instant::from_ticks(0),
			next_diag_at: Instant::from_ticks(0),
			cached_link: false,
		}
	}

	fn scan_phys(&mut self) {
		let mut found = [u8::MAX; 4];
		let mut idx = 0usize;

		for addr in 0u8..32 {
			let id1 = self.sm.smi_read(addr, 0x02);
			let id2 = self.sm.smi_read(addr, 0x03);

			if id1 == 0 || id1 == 0xFFFF {
				continue;
			}

			info!("PHY probe addr={} id1={} id2={}", addr, id1, id2);

			if id1 == 0x0022 && (id2 & 0xFFF0) == 0x1430 && idx < found.len() {
				found[idx] = addr;
				idx += 1;
			}
		}

		if idx >= 2 {
			self.port_phys = found;
			self.port_phys_count = idx;
			info!(
				"Using {} KSZ PHY addrs: {}, {}, {}, {}",
				self.port_phys_count,
				self.port_phys[0],
				self.port_phys[1],
				self.port_phys[2],
				self.port_phys[3]
			);
		} else {
			warn!(
				"KSZ PHY auto-detect incomplete (found {}), keeping defaults {}, {}",
				idx,
				self.port_phys[0],
				self.port_phys[1]
			);
			self.port_phys_count = 2;
		}
	}

	fn read_link_latched(&mut self, phy_addr: u8) -> bool {
		self.with_miim(|bus| {
			let mut phy = bus.phy(phy_addr);
			let _ = phy.bsr().read();
			let bsr = match phy.bsr().read() {
				Ok(v) => v,
				Err(err) => match err {},
			};
			bsr.read().link_status().bit_is_set()
		})
	}

	fn with_miim<R>(&mut self, f: impl FnOnce(&mut ksz8863::Miim<KszMiim<'_, SM>>) -> R) -> R {
		let iface = KszMiim { sm: &mut self.sm };
		let mut miim_bus = ksz8863::Miim(iface);
		f(&mut miim_bus)
	}

	fn any_port_link_up(&mut self) -> bool {
		let port_phys = self.port_phys;
		let n = self.port_phys_count;
		let mut ext_link = false;
		let mut cpu_link = false;

		for phy_addr in port_phys[..n].iter().copied() {
			let up = self.read_link_latched(phy_addr);
			if !up {
				continue;
			}

			if phy_addr == 3 {
				cpu_link = true;
			} else {
				ext_link = true;
			}
		}

		if !ext_link && cpu_link {
			warn!("No external PHY link, using PHY3 link fallback");
		}

		ext_link || cpu_link
	}

	fn diag_ports(&mut self) {
		let port_phys = self.port_phys;
		let n = self.port_phys_count;
		let mut link_bits = 0u8;
		for phy_addr in port_phys[..n].iter().copied() {
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
				phy_addr,
				id1,
				id2,
				bcr_raw,
				bsr_raw,
				link,
				an_done,
			);
		}

		PHY_LINK_BITS.store(link_bits, Ordering::Relaxed);
	}
}

impl<SM: StationManagement> Phy for Ksz8863Phy<SM> {
	fn phy_reset(&mut self) {
		self.scan_phys();

		let port_phys = self.port_phys;
		let n = self.port_phys_count;
		self.with_miim(|bus| {
			for phy_addr in port_phys[..n].iter().copied() {
				let mut phy = bus.phy(phy_addr);
				let _ = phy.bcr().write(|w| w.reset());
			}
		});
	}

	fn phy_init(&mut self) {
		let port_phys = self.port_phys;
		let n = self.port_phys_count;
		self.with_miim(|bus| {
			for phy_addr in port_phys[..n].iter().copied() {
				let mut phy = bus.phy(phy_addr);

				// Config link to STM
				if phy_addr == 3 {
					let _ = phy.bcr().write(|w| {
						w.an_enable()
							.clear_bit()// Disable Auto-Link-Negotiation if setting speed manually
							.force_100()
							.set_bit()
							.force_fd()
							.set_bit()
							.power_down()
							.clear_bit()
							.disable_transmit()
							.clear_bit()
					});
					info!("Configured PHY {} as forced 100M/full-duplex", phy_addr);
				// Config 2 external conns
				} else {
					let _ = phy.bcr().modify(|w| {
						w.an_enable()
							.clear_bit()
							.restart_an()
							.set_bit()
							.force_100()
							.clear_bit() // 10BASE-T is more stable than 100BASE-T
							.power_down()
							.clear_bit()
							.disable_transmit()
							.clear_bit()
					});
					info!("Configured PHY {} for autoneg", phy_addr);
				}
			}
		});
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

struct KszMiim<'a, SM: StationManagement> {
	sm: &'a mut SM,
}

impl<SM: StationManagement> mdio::miim::Read for KszMiim<'_, SM> {
	type Error = Infallible;

	fn read(&mut self, phy_addr: u8, reg_addr: u8) -> Result<u16, Self::Error> {
		Ok(self.sm.smi_read(phy_addr, reg_addr))
	}
}

impl<SM: StationManagement> mdio::miim::Write for KszMiim<'_, SM> {
	type Error = Infallible;

	fn write(&mut self, phy_addr: u8, reg_addr: u8, data: u16) -> Result<(), Self::Error> {
		self.sm.smi_write(phy_addr, reg_addr, data);
		Ok(())
	}
}
