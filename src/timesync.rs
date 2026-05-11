use defmt::{info, warn};
use embassy_net::{IpEndpoint, Stack, dns::DnsQueryType, udp::{PacketMetadata, UdpSocket}};
use embassy_time::{Duration, Instant, Timer, with_timeout};


// internet time sync (NTP)
const NTP_ADDR: &str = "pool.ntp.org";
const NTP_PORT: u16 = 123;
const NTP_UNIX_EPOCH_DIFF_SECS: u64 = 2_208_988_800;

fn ntp_packet_to_unix_micros(packet: &[u8]) -> Option<u64> {
    if packet.len() < 48 {
        return None;
    }

    let secs = u32::from_be_bytes([packet[40], packet[41], packet[42], packet[43]]) as u64;
    let frac = u32::from_be_bytes([packet[44], packet[45], packet[46], packet[47]]) as u64;
    if secs < NTP_UNIX_EPOCH_DIFF_SECS {
        return None;
    }

    let unix_secs = secs - NTP_UNIX_EPOCH_DIFF_SECS;
    let micros_from_frac = (frac * 1_000_000) >> 32;
    Some(unix_secs.saturating_mul(1_000_000).saturating_add(micros_from_frac))
}

async fn try_sync_internet_time(stack: &Stack<'_>) -> Result<u64, &'static str> {
    let ips = stack
        .dns_query(NTP_ADDR, DnsQueryType::A)
        .await
        .map_err(|_| "dns")?;
    let Some(ip) = ips.first() else {
        return Err("dns-empty");
    };

    let mut rx_meta = [PacketMetadata::EMPTY; 1];
    let mut tx_meta = [PacketMetadata::EMPTY; 1];
    let mut rx_buf = [0u8; 96];
    let mut tx_buf = [0u8; 96];
    let mut socket = UdpSocket::new(*stack, &mut rx_meta, &mut rx_buf, &mut tx_meta, &mut tx_buf);
    socket.bind(0).map_err(|_| "bind")?;

    let endpoint = IpEndpoint::new((*ip).into(), NTP_PORT);
    let mut request = [0u8; 48];
    request[0] = 0x23; // LI=0, VN=4, Mode=3 (client)

    let t0 = Instant::now().as_micros();
    socket.send_to(&request, endpoint).await.map_err(|_| "send")?;

    let mut response = [0u8; 48];
    let (len, _src) = with_timeout(Duration::from_secs(3), socket.recv_from(&mut response))
        .await
        .map_err(|_| "timeout")?
        .map_err(|_| "recv")?;
    let t1 = Instant::now().as_micros();

    let Some(mut unix_us) = ntp_packet_to_unix_micros(&response[..len]) else {
        return Err("parse");
    };

    unix_us = unix_us.saturating_add((t1 - t0) / 2);
    Ok(unix_us)
}

pub async fn sync_internet_time(stack: &Stack<'_>) -> u64 {
    for attempt in 1..=10 {
        match try_sync_internet_time(stack).await {
            Ok(unix_us) => {
                info!("internet time synced on attempt {}", attempt);
                return unix_us;
            }
            Err(e) => {
                warn!("internet time sync failed ({}): {}", attempt, e);
                Timer::after_secs(2).await;
            }
        }
    }

    warn!("internet time unavailable, using monotonic fallback");
    0
}
