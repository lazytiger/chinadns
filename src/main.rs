use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufRead, BufReader, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_std::net::UdpSocket;
use async_std::prelude::*;
use async_std::task;
use clap::Clap;
use trust_dns_server::authority::MessageRequest;
use trust_dns_server::proto::serialize::binary::{BinDecodable, BinDecoder};

use lazy_static::lazy_static;

struct IpRange {
    low: u32,
    high: u32,
}

impl IpRange {
    fn new(low: u32, high: u32) -> IpRange {
        IpRange { low, high }
    }

    fn contains(&self, ip: u32) -> bool {
        self.low <= ip && ip <= self.high
    }
}

struct IpSet {
    data: Vec<IpRange>,
}

impl IpSet {
    fn new(file: String) -> IpSet {
        let mut set = IpSet { data: Vec::new() };
        set.init(file);
        set
    }

    fn ip2int(ip: Ipv4Addr) -> u32 {
        let some = ip.octets();
        (some[0] as u32) << 24 | (some[1] as u32) << 16 | (some[2] as u32) << 8 | (some[3] as u32)
    }

    fn init(&mut self, file: String) {
        if let Ok(file) = File::open(file) {
            let reader = BufReader::new(file);
            self.data = reader
                .lines()
                .filter_map(|line| {
                    if let Ok(line) = line {
                        if line.contains("add") {
                            if let Some(cidr) = line.split(' ').nth(2) {
                                let data: Vec<&str> = cidr.split('/').collect();
                                if data.len() == 1 {
                                    if let Ok(ip) = Ipv4Addr::from_str(data[0]) {
                                        let ip = Self::ip2int(ip);
                                        Some(IpRange::new(ip, ip))
                                    } else {
                                        None
                                    }
                                } else if data.len() == 2 {
                                    if let Ok(ip) = Ipv4Addr::from_str(data[0]) {
                                        if let Ok(mask) = u32::from_str(data[1]) {
                                            let mut ip = Self::ip2int(ip);
                                            let mask = (1 << (32 - mask)) - 1;
                                            if ip != ip & !mask {
                                                log::error!("invalid ipset file format");
                                                ip &= !mask;
                                            }
                                            Some(IpRange::new(ip, ip + mask))
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();
        } else {
            return;
        }
        self.data.sort_by(|d1, d2| {
            let n = d1.low as i32 - d2.low as i32;
            match n {
                _ if n < 0 => Ordering::Less,
                _ if n == 0 => Ordering::Equal,
                _ if n > 0 => Ordering::Greater,
                _ => unreachable!(),
            }
        });
    }

    fn test(&self, ip: IpAddr) -> bool {
        if let IpAddr::V4(v4) = ip {
            let ip = Self::ip2int(v4);
            self.binary_search(ip)
        } else {
            false
        }
    }

    fn binary_search(&self, ip: u32) -> bool {
        let mut low = 0;
        let mut high = self.data.len();
        while low < high {
            let pos = (high + low) / 2;
            let data = &self.data[pos];
            if data.contains(ip) {
                return true;
            } else if data.high < ip {
                low = pos + 1;
            } else if data.low > ip {
                high = pos.saturating_sub(1);
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    use crate::IpSet;

    #[test]
    fn test() {
        let set = IpSet::new("/etc/chinaipset".into());
        println!("data length is {}", set.data.len());

        //let ip = Ipv4Addr::from_str("114.114.114.114").unwrap();
        let ip = Ipv4Addr::from_str("103.31.160.0").unwrap();
        assert!(set.test(IpAddr::V4(ip)));

        let ip = Ipv4Addr::from_str("103.31.160.1").unwrap();
        assert!(set.test(IpAddr::V4(ip)));
    }
}

#[derive(Clap)]
#[clap(
    version = "0.1",
    author = "Hoping White",
    about = "A chinadns implementation using rust"
)]
struct Config {
    #[clap(short, long, about = "trust dns address, ip:port")]
    trust_dns: String,
    #[clap(short, long, about = "china dns address, ip:port")]
    china_dns: String,
    #[clap(short = "i", long, about = "china address ipset")]
    china_ipset: String,
    #[clap(short, long, about = "chinadns listen address, ip:port")]
    listen_addr: String,
    #[clap(short = "f", long, about = "log file path")]
    log_file: Option<String>,
    #[clap(
        short = "o",
        long,
        about = "log level, 0:trace, 1:debug, 2:info, 3:warning, 4:error"
    )]
    log_level: u8,
    #[clap(short = "m", long, about = "timeout time for request")]
    timeout: u64,
}

struct RConfig {
    trust_addr: SocketAddr,
    china_addr: SocketAddr,
    timeout_duration: Duration,
}

lazy_static! {
    static ref CONFIG: Config = Config::parse();
    static ref RCONFIG: RConfig = {
        let trust_addr = CONFIG.trust_dns.as_str().parse().unwrap();
        let china_addr = CONFIG.china_dns.as_str().parse().unwrap();
        let timeout_duration = Duration::new(CONFIG.timeout, 0);
        RConfig {
            trust_addr,
            china_addr,
            timeout_duration,
        }
    };
    static ref IPSET: IpSet = IpSet::new(CONFIG.china_ipset.clone());
}

fn setup_logger(logfile: &Option<String>, level: u8) {
    let level = match level {
        0x00 => log::LevelFilter::Trace,
        0x01 => log::LevelFilter::Debug,
        0x02 => log::LevelFilter::Info,
        0x03 => log::LevelFilter::Warn,
        0x04 => log::LevelFilter::Error,
        _ => log::LevelFilter::Off,
    };
    let mut builder = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}:{}][{}]{}",
                chrono::Local::now().format("[%Y-%m-%d %H:%M:%S%.6f]"),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.level(),
                message
            ))
        })
        .level(level);
    if logfile.is_some() {
        cfg_if::cfg_if! {
            if #[cfg(unix)] {
                let path = std::path::Path::new(logfile.as_ref().unwrap().as_str());
                builder = builder.chain(fern::log_reopen(path, Some(libc::SIGUSR2)).unwrap());
            } else {
                builder = builder.chain(fern::log_file(logfile.as_ref().unwrap()).unwrap());
            }
        }
    } else {
        builder = builder.chain(std::io::stdout());
    }
    builder.apply().unwrap();
}

#[async_std::main]
async fn main() -> Result<()> {
    setup_logger(&CONFIG.log_file, CONFIG.log_level);
    log::warn!("server started");
    let listener = Arc::new(UdpSocket::bind(CONFIG.listen_addr.as_str()).await?);
    let mut buf = vec![0u8; 1024];
    log::warn!("start listening");
    loop {
        let (size, addr) = listener.recv_from(&mut buf).await?;
        let mut decoder = BinDecoder::new(&buf.as_slice()[..size]);
        let request = MessageRequest::read(&mut decoder)?;
        task::spawn(dispatch(request, addr, buf.clone(), size, listener.clone()));
    }
}

async fn receive(
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    sender: Arc<UdpSocket>,
    count: usize,
) -> Result<bool> {
    let mut data = vec![0u8; 1024];
    let (size, dst_addr) = socket.recv_from(&mut data).await?;
    let mut decoder = BinDecoder::new(&data.as_slice()[..size]);
    let response = MessageRequest::read(&mut decoder)?;
    if dst_addr == RCONFIG.china_addr {
        if count == 1 {
            log::info!("china dns return first, checking");
        }
        if response
            .answers()
            .iter()
            .filter_map(|r| r.rdata().to_ip_addr())
            .filter_map(|ip| {
                if IPSET.test(ip) {
                    None
                } else {
                    log::info!("china dns received foreign address, ignore");
                    Some(())
                }
            })
            .count()
            == 0
        {
            log::info!("china dns returned chinese address, it's ok to send");
            sender.send_to(&data.as_slice()[..size], addr).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    } else if dst_addr == RCONFIG.trust_addr {
        if count == 1 {
            log::info!("trust dns returned first");
        }
        log::info!("send trust dns result to client");
        sender.send_to(&data.as_slice()[..size], addr).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn dispatch(
    request: MessageRequest,
    addr: SocketAddr,
    data: Vec<u8>,
    size: usize,
    sender: Arc<UdpSocket>,
) -> Result<()> {
    log::debug!("udp request:{:?}", request.queries()[0].name());
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    socket
        .send_to(&data.as_slice()[..size], RCONFIG.trust_addr)
        .await?;
    socket
        .send_to(&data.as_slice()[..size], RCONFIG.china_addr)
        .await?;
    let t1 = async {
        let mut count = 0;
        loop {
            count += 1;
            if let Ok(ok) = receive(socket.clone(), addr, sender.clone(), count).await {
                if ok {
                    break;
                }
            }
        }
    };
    let t2 = task::sleep(RCONFIG.timeout_duration);
    t1.race(t2).await;
    Ok(())
}
