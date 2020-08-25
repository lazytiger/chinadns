use std::io::Result;
use std::net::{SocketAddr};

use async_std::net::UdpSocket;
use async_std::task;
use trust_dns_server::authority::MessageRequest;
use trust_dns_server::proto::serialize::binary::{BinDecodable, BinDecoder};
use std::sync::Arc;
use crate::ipset::IpSet;

mod ipset;

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
    IpSet::init();
    let set = IpSet::new("gfwlist".into());
    set.create();
    if set.test("8.8.8.8".into()) {
        println!("contains")
    }
    setup_logger(&None, 0);
    let listener = Arc::new(UdpSocket::bind("127.0.0.1:53").await?);
    let mut buf = vec![0u8; 1024];
    loop {
        let (size, addr) = listener.recv_from(&mut buf).await?;
        let mut decoder = BinDecoder::new(&buf.as_slice()[..size]);
        let request = MessageRequest::read(&mut decoder)?;
        task::spawn(dispatch(request, addr, buf.clone(), size, listener.clone()));
    }
}

async fn dispatch(request: MessageRequest, addr: SocketAddr, mut data: Vec<u8>, size: usize, sender:Arc<UdpSocket>) -> Result<()> {
    log::debug!("udp request:{:?}", request);
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.send_to(&data.as_slice()[..size], "114.114.114.114:53").await?;
    let (size, dst_addr) = socket.recv_from(&mut data).await?;
    let mut decoder = BinDecoder::new(&data.as_slice()[..size]);
    let response = MessageRequest::read(&mut decoder)?;
    response.answers().iter().filter_map(|r|{r.rdata().to_ip_addr()}).filter_map(|ip|{Some(true)}).count();
    log::debug!("{:?} send response:{:?}", dst_addr, response);
    sender.send_to(&data.as_slice()[..size], addr).await?;
    Ok(())
}
