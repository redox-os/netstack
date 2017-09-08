extern crate event;
extern crate syscall;
extern crate smoltcp;

use error::{Error, Result};
use event::EventQueue;
use scheme::Smolnetd;
use std::os::unix::io::{FromRawFd, RawFd};
use std::process;
use std::rc::Rc;
use std::fs::File;
use std::cell::RefCell;

mod error;
mod scheme;

fn run() -> Result<()> {
    use syscall::flag::*;

    if unsafe { syscall::clone(0).unwrap() } != 0 {
        return Ok(());
    }

    println!("icmpd: opening network:");
    let network_fd = syscall::open("network:", O_RDWR | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open network:"))? as
        RawFd;

    println!("icmpd: opening :ip");
    let ip_fd = syscall::open(":ip", O_RDWR | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open :ip"))? as RawFd;

    let (network_file, ip_file) =
        unsafe { (File::from_raw_fd(network_fd), File::from_raw_fd(ip_fd)) };
    let smolnetd = Rc::new(RefCell::new(Smolnetd::new(network_file, ip_file)));

    let mut event_queue = EventQueue::<(), Error>::new()
        .map_err(|e| Error::from_io_error(e, "failed to create event queue"))?;

    let smolnetd_ = smolnetd.clone();

    event_queue
        .add(network_fd, move |_| {
            smolnetd_.borrow_mut().on_network_scheme_event()
        })
        .map_err(|e| {
            Error::from_io_error(e, "failed to listen to network events")
        })?;

    event_queue
        .add(ip_fd, move |_| smolnetd.borrow_mut().on_ip_scheme_event())
        .map_err(|e| Error::from_io_error(e, "failed to listen to ip events"))?;

    event_queue.run()
}

fn main() {
    if let Err(err) = run() {
        println!("smoltcpd: {}", err);
        process::exit(1);
    }
    process::exit(0);
}
