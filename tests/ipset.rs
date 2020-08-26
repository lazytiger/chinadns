use std::net::Ipv4Addr;

#[test]
fn test() {
    let set = IpSet::new("/etc/chinaipset");
    let ip = Ipv4Addr::from_str("114.114.114.114").unwrap();
    assert!(set.test(ip));
}