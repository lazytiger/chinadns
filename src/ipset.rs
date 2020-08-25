#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[no_mangle]
pub unsafe extern "C" fn rust_error_callback(_: *mut ipset, p: *mut c_void, status: c_int, msg: *const c_char) -> c_int {
    let mut ipset = Box::from_raw(p as *mut IpSet);
    let msg = CStr::from_ptr(msg);
    let msg = msg.to_string_lossy();
    log::trace!("error callback:{}, {}", status, msg);
    ipset.set_result(status as isize, msg.into());
    let _ = Box::into_raw(ipset);

    0
}

pub struct IpSet {
    name: String,
    set: *mut ipset,
    result: String,
    status: isize,
}

impl IpSet {
    pub fn init() {
        unsafe {
            ipset_load_types();
        }
    }

    pub fn new(name: String) -> Box<IpSet> {
        let mut set = Box::new(IpSet {
            name,
            set: unsafe { ipset_init() },
            result: String::new(),
            status: 0,
        });
        unsafe {
            ipset_custom_printf(set.set, Some(error_callback), None, None, set.as_mut() as *mut IpSet as *mut c_void);
        }
        set
    }

    fn set_result(&mut self, status: isize, result: String) {
        self.status = status;
        self.result = result;
    }

    pub fn create(&self) -> bool {
        self.execute("create", "hash:ip")
    }

    pub fn add(&self, ip: &str) -> bool {
        self.execute("add", ip)
    }

    pub fn del(&self, ip: &str) -> bool {
        self.execute("del", ip)
    }

    pub fn test(&self, ip: &str) -> bool {
        self.execute("test", ip);
        if self.status == 0 && !self.result.contains("NOT") {
            true
        } else {
            false
        }
    }

    fn execute(&self, action: &str, param: &str) -> bool {
        let cmd = format!("{} {} {}", action, self.name, param);
        log::trace!("execute {}", cmd);
        let cmd = CString::new(cmd).unwrap();
        unsafe {
            ipset_parse_line(self.set, cmd.as_ptr() as *mut c_char);
        }
        self.status == 0
    }
}

impl Drop for IpSet {
    fn drop(&mut self) {
        unsafe {
            ipset_fini(self.set);
        }
    }
}

unsafe impl Send for IpSet {}

unsafe impl Sync for IpSet {}

#[cfg(test)]
mod tests {
    use test::Bencher;

    use crate::ipset::IpSet;

    #[test]
    fn test() {
        let set = IpSet::new("gfwlist".into());
        set.execute("test".into(), "8.8.8.8".into());
    }

    #[bench]
    fn benchmark(b: &mut Bencher) {
        let set = IpSet::new("gfwlist".into());
        b.iter(|| set.test("8.8.8.8"));
    }
}