use core::task::Context;

use defmt::info;
use embassy_stm32::{eth::Phy, gpio::Output, spi::Spi};
use embassy_time::{Duration, Instant};

pub struct Ksz8863Phy<'a> {
    spi: Spi<'a, embassy_stm32::mode::Blocking, embassy_stm32::spi::mode::Master>,
    cs: Output<'static>,
    led_phy: [Output<'static>; 2],
    next_poll_at: Instant,
    next_diag_at: Instant,
    cached_link: bool,
}

impl<'a> Ksz8863Phy<'a> {
    pub fn new(
        spi: Spi<'a, embassy_stm32::mode::Blocking, embassy_stm32::spi::mode::Master>,
        cs: Output<'static>,
        led_phy: [Output<'static>; 2],
    ) -> Self {
        Self {
            spi,
            cs,
            led_phy,
            next_poll_at: Instant::from_ticks(0),
            next_diag_at: Instant::from_ticks(0),
            cached_link: false,
        }
    }
    fn reg_write(&mut self, reg: u8, value: u8) {
        self.cs.set_low();
        self.spi
            .blocking_transfer_in_place(&mut [0x02, reg, value])
            .unwrap();
        self.cs.set_high();
    }
    fn reg_read(&mut self, reg: u8) -> u8 {
        let mut buffer = [0u8; 3];
        buffer[0] = 0x03; // Read Instruction
        buffer[1] = reg; // Register Address
        buffer[2] = 0x00; // Placeholder for shifted-out data

        self.cs.set_low();
        self.spi.blocking_transfer_in_place(&mut buffer).unwrap();
        self.cs.set_high();

        // Return register output
        buffer[2]
    }
    fn set_p3_ref_clk(&mut self, internal: bool) {
        let mut value = self.reg_read(0xC6);
        value = (value & !(1 << 3)) | ((internal as u8) << 3);
        self.reg_write(0xC6, value);
    }
    fn set_control(
        &mut self,
        port: u8,
        auto_negotiate: bool,
        force_speed_100: bool,
        force_duplex: bool,
    ) {
        let reg = match port {
            1 => 0x1C,
            2 => 0x2C,
            _ => core::panic!(),
        };
        let mut val = auto_negotiate as u8;
        val = (val << 1) + (force_speed_100 as u8);
        val = (val << 1) + (force_duplex as u8);
        val = (val << 5) + (0b11111u8);
        self.reg_write(reg, val);
    }
    fn get_auto_negotiate(&mut self, port: u8) -> bool {
        let reg = match port {
            1 => 0x1C,
            2 => 0x2C,
            _ => core::panic!(),
        };
        (self.reg_read(reg) >> 7) & 0b1 != 0
    }
    fn get_force_speed_100(&mut self, port: u8) -> bool {
        let reg = match port {
            1 => 0x1C,
            2 => 0x2C,
            _ => core::panic!(),
        };
        (self.reg_read(reg) >> 6) & 0b1 != 0
    }
    fn get_force_duplex(&mut self, port: u8) -> bool {
        let reg = match port {
            1 => 0x1C,
            2 => 0x2C,
            _ => core::panic!(),
        };
        (self.reg_read(reg) >> 5) & 0b1 != 0
    }
    fn get_link_good(&mut self, port: u8) -> bool {
        let reg = match port {
            1 => 0x1E,
            2 => 0x2E,
            _ => core::panic!(),
        };
        (self.reg_read(reg) >> 5) & 0b1 != 0
    }
    fn get_an_done(&mut self, port: u8) -> bool {
        let reg = match port {
            1 => 0x1E,
            2 => 0x2E,
            _ => core::panic!(),
        };
        (self.reg_read(reg) >> 6) & 0b1 != 0
    }

    fn any_port_link_up(&mut self) -> bool {
        self.get_link_good(1) || self.get_link_good(2)
    }

    fn diag_ports(&mut self) {
        for port in 1..2 {
            let link = self.get_link_good(port);
            let an_done = self.get_an_done(port);
            let auto_negotiate = self.get_auto_negotiate(port);
            let force_speed_100 = self.get_force_speed_100(port);
            let force_duplex = self.get_force_duplex(port);
            info!(
                "Port {} link={} an_done={} auto_negotiate={} force_speed_100={} force_duplex={}",
                port, link, an_done, auto_negotiate, force_speed_100, force_duplex
            );

            self.led_phy[port as usize].set_level(link.into());
        }
    }
}

impl Phy for Ksz8863Phy<'_> {
    fn phy_reset(&mut self) {
        // Reset the switch (Register 67: reset)
        self.reg_write(0x43, 1 << 4);
    }

    fn phy_init(&mut self) {
        self.phy_reset();
        self.set_p3_ref_clk(true);
        self.set_control(1, true, true, true);
        self.set_control(2, true, true, true);
    }

    fn poll_link(&mut self, cx: &mut Context) -> bool {

        const POLL_INTERVALL: Duration = Duration::from_millis(300);

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
        self.next_poll_at = now + POLL_INTERVALL;
        self.cached_link
    }
}

// struct Ksz8863Phy<SM: StationManagement> {
//     sm: SM,
//     port_phys: [u8; 4],
//     port_phys_count: usize,
//     poll_interval: Duration,
//     next_poll_at: Instant,
//     next_diag_at: Instant,
//     cached_link: bool,
// }
// 
// impl<SM: StationManagement> Ksz8863Phy<SM> {
//     fn new(sm: SM, port_phys: [u8; 2]) -> Self {
//         let mut phy_addrs = [u8::MAX; 4];
//         phy_addrs[0] = port_phys[0];
//         phy_addrs[1] = port_phys[1];
// 
//         Self {
//             sm,
//             port_phys: phy_addrs,
//             port_phys_count: 2,
//             poll_interval: Duration::from_millis(300),
//             next_poll_at: Instant::from_ticks(0),
//             next_diag_at: Instant::from_ticks(0),
//             cached_link: false,
//         }
//     }
// 
//     fn scan_phys(&mut self) {
//         let mut found = [u8::MAX; 4];
//         let mut idx = 0usize;
// 
//         for addr in 0u8..32 {
//             let id1 = self.sm.smi_read(addr, 0x02);
//             let id2 = self.sm.smi_read(addr, 0x03);
// 
//             if id1 == 0 || id1 == 0xFFFF {
//                 continue;
//             }
// 
//             info!("PHY probe addr={} id1={} id2={}", addr, id1, id2);
// 
//             if id1 == 0x0022 && (id2 & 0xFFF0) == 0x1430 && idx < found.len() {
//                 found[idx] = addr;
//                 idx += 1;
//             }
//         }
// 
//         if idx >= 2 {
//             self.port_phys = found;
//             self.port_phys_count = idx;
//             info!(
//                 "Using {} KSZ PHY addrs: {}, {}, {}, {}",
//                 self.port_phys_count,
//                 self.port_phys[0],
//                 self.port_phys[1],
//                 self.port_phys[2],
//                 self.port_phys[3]
//             );
//         } else {
//             warn!(
//                 "KSZ PHY auto-detect incomplete (found {}), keeping defaults {}, {}",
//                 idx, self.port_phys[0], self.port_phys[1]
//             );
//             self.port_phys_count = 2;
//         }
//     }
// 
//     fn read_link_latched(&mut self, phy_addr: u8) -> bool {
//         self.with_miim(|bus| {
//             let mut phy = bus.phy(phy_addr);
//             let _ = phy.bsr().read();
//             let bsr = match phy.bsr().read() {
//                 Ok(v) => v,
//                 Err(err) => match err {},
//             };
//             bsr.read().link_status().bit_is_set()
//         })
//     }
// 
//     fn with_miim<R>(&mut self, f: impl FnOnce(&mut ksz8863::Miim<KszMiim<'_, SM>>) -> R) -> R {
//         let iface = KszMiim { sm: &mut self.sm };
//         let mut miim_bus = ksz8863::Miim(iface);
//         f(&mut miim_bus)
//     }
// 
//     fn any_port_link_up(&mut self) -> bool {
//         let port_phys = self.port_phys;
//         let n = self.port_phys_count;
//         let mut ext_link = false;
//         let mut cpu_link = false;
// 
//         for phy_addr in port_phys[..n].iter().copied() {
//             let up = self.read_link_latched(phy_addr);
//             if !up {
//                 continue;
//             }
// 
//             if phy_addr == 3 {
//                 cpu_link = true;
//             } else {
//                 ext_link = true;
//             }
//         }
// 
//         if !ext_link && cpu_link {
//             warn!("No external PHY link, using PHY3 link fallback");
//         }
// 
//         ext_link || cpu_link
//     }
// 
//     fn diag_ports(&mut self) {
//         let port_phys = self.port_phys;
//         let n = self.port_phys_count;
//         let mut link_bits = 0u8;
//         for phy_addr in port_phys[..n].iter().copied() {
//             let id1 = self.sm.smi_read(phy_addr, 0x02);
//             let id2 = self.sm.smi_read(phy_addr, 0x03);
//             let bsr_raw = self.sm.smi_read(phy_addr, 0x01); // status register
//             let bcr_raw = self.sm.smi_read(phy_addr, 0x00); // config register
//             let link = (bsr_raw & (1 << 2)) != 0;
//             let an_done = (bsr_raw & (1 << 5)) != 0;
// 
//             if link && (1..=3).contains(&phy_addr) {
//                 link_bits |= 1 << (phy_addr - 1);
//             }
// 
//             info!(
//                 "PHY {} id1={} id2={} config={:b} status={:b} link={} an_done={}",
//                 phy_addr, id1, id2, bcr_raw, bsr_raw, link, an_done,
//             );
//         }
// 
//         PHY_LINK_BITS.store(link_bits, Ordering::Relaxed);
//     }
// }
// 
// impl<SM: StationManagement> Phy for Ksz8863Phy<SM> {
//     fn phy_reset(&mut self) {
//         self.scan_phys();
// 
//         let port_phys = self.port_phys;
//         let n = self.port_phys_count;
//         self.with_miim(|bus| {
//             for phy_addr in port_phys[..n].iter().copied() {
//                 let mut phy = bus.phy(phy_addr);
//                 let _ = phy.bcr().write(|w| w.reset());
//             }
//         });
//     }
// 
//     fn phy_init(&mut self) {
//         let port_phys = self.port_phys;
//         let n = self.port_phys_count;
//         self.with_miim(|bus| {
//             for phy_addr in port_phys[..n].iter().copied() {
//                 let mut phy = bus.phy(phy_addr);
// 
//                 // Config link to STM
//                 if phy_addr == 3 {
//                     let _ = phy.bcr().write(|w| {
//                         w.an_enable()
//                             .clear_bit() // Disable Auto-Link-Negotiation if setting speed manually
//                             .force_100()
//                             .set_bit()
//                             .force_fd()
//                             .set_bit()
//                             .power_down()
//                             .clear_bit()
//                             .disable_transmit()
//                             .clear_bit()
//                     });
//                     info!("Configured PHY {} as forced 100M/full-duplex", phy_addr);
//                 // Config 2 external conns
//                 } else {
//                     let _ = phy.bcr().modify(|w| {
//                         w.an_enable()
//                             .clear_bit()
//                             .restart_an()
//                             .set_bit()
//                             .force_100()
//                             .clear_bit() // 10BASE-T is more stable than 100BASE-T
//                             .power_down()
//                             .clear_bit()
//                             .disable_transmit()
//                             .clear_bit()
//                     });
//                     info!("Configured PHY {} for autoneg", phy_addr);
//                 }
//             }
//         });
//     }
// 
//     fn poll_link(&mut self, cx: &mut Context) -> bool {
//         let now = Instant::now();
//         if now >= self.next_diag_at {
//             self.diag_ports();
//             self.next_diag_at = now + Duration::from_secs(2);
//         }
// 
//         if now < self.next_poll_at {
//             cx.waker().wake_by_ref();
//             return self.cached_link;
//         }
// 
//         self.cached_link = self.any_port_link_up();
//         self.next_poll_at = now + self.poll_interval;
//         self.cached_link
//     }
// }

// struct KszMiim<'a, SM: StationManagement> {
//     sm: &'a mut SM,
// }
// 
// impl<SM: StationManagement> mdio::miim::Read for KszMiim<'_, SM> {
//     type Error = Infallible;
// 
//     fn read(&mut self, phy_addr: u8, reg_addr: u8) -> Result<u16, Self::Error> {
//         Ok(self.sm.smi_read(phy_addr, reg_addr))
//     }
// }
// 
// impl<SM: StationManagement> mdio::miim::Write for KszMiim<'_, SM> {
//     type Error = Infallible;
// 
//     fn write(&mut self, phy_addr: u8, reg_addr: u8, data: u16) -> Result<(), Self::Error> {
//         self.sm.smi_write(phy_addr, reg_addr, data);
//         Ok(())
//     }
// }
