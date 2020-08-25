use std::io::{Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_std::net::UdpSocket;
use async_std::prelude::*;
use async_std::task;
use clap::Clap;
use trust_dns_server::authority::MessageRequest;
use trust_dns_server::proto::serialize::binary::{BinDecodable, BinDecoder};

use lazy_static::lazy_static;

use crate::ipset::IpSet;

mod ipset;

#[derive(Clap)]
#[clap(version = "0.1", author = "Hoping White", about = "A chinadns implementation using rust")]
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
    #[clap(short = "o", long, about = "log level, 0:trace, 1:debug, 2:info, 3:warning, 4:error")]
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
    static ref CONFIG: Config = {
        Config::parse()
    };
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
    static ref IPSET: Box<IpSet> = {
        IpSet::init();
        IpSet::new(CONFIG.china_ipset.clone())
    };
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
    let listener = Arc::new(UdpSocket::bind(CONFIG.listen_addr.as_str()).await?);
    let mut buf = vec![0u8; 1024];
    loop {
        let (size, addr) = listener.recv_from(&mut buf).await?;
        let mut decoder = BinDecoder::new(&buf.as_slice()[..size]);
        let request = MessageRequest::read(&mut decoder)?;
        task::spawn(dispatch(request, addr, buf.clone(), size, listener.clone()));
    }
}

async fn receive(socket: Arc<UdpSocket>, addr: SocketAddr, sender: Arc<UdpSocket>) -> Result<bool> {
    let mut data = vec![0u8; 1024];
    let (size, dst_addr) = socket.recv_from(&mut data).await?;
    let mut decoder = BinDecoder::new(&data.as_slice()[..size]);
    let response = MessageRequest::read(&mut decoder)?;
    log::debug!("{:?} send response:{:?}", dst_addr, response);
    if dst_addr == RCONFIG.china_addr {
        if response.answers().iter().filter_map(|r| { r.rdata().to_ip_addr() }).filter_map(|ip| {
            if IPSET.test(ip.to_string().as_str()) {
                None
            } else {
                Some(())
            }
        }).count() == 0 {
            log::debug!("china dns returned");
            sender.send_to(&data.as_slice()[..size], addr).await?;
            return Ok(true);
        } else {
            Ok(false)
        }
    } else if dst_addr == RCONFIG.trust_addr {
        log::debug!("trust dns returned");
        sender.send_to(&data.as_slice()[..size], addr).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn dispatch(request: MessageRequest, addr: SocketAddr, data: Vec<u8>, size: usize, sender: Arc<UdpSocket>) -> Result<()> {
    log::debug!("udp request:{:?}", request);
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    socket.send_to(&data.as_slice()[..size], RCONFIG.trust_addr).await?;
    socket.send_to(&data.as_slice()[..size], RCONFIG.china_addr).await?;
    let t1 = async {
        loop {
            if let Ok(ok)= receive(socket.clone(), addr, sender.clone()).await {
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
