extern crate event;
extern crate syscall;
extern crate netutils;

use error::{Result, Error};
use event::EventQueue;
use scheme::Icmpd;
use std::cell::RefCell;
use std::fs::File;
use std::os::unix::io::{RawFd, FromRawFd};
use std::process;
use std::rc::Rc;

mod error;
mod packet;
mod scheme;

fn run() -> Result<()> {
    use syscall::flag::*;

    // if unsafe { syscall::clone(0).unwrap() } != 0 {
    //     return Ok(());
    // }

    println!("icmpd: opening ip:1:");
    let icmp_fd = syscall::open("ip:1", O_RDWR | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open ip:1"))? as
                  RawFd;

    println!("icmpd: prividing icmp:");
    let scheme_fd = syscall::open(":icmp", O_RDWR | O_CREAT | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open :icmp"))? as
                    RawFd;

    let icmpd = Rc::new(RefCell::new(Icmpd::new(unsafe { File::from_raw_fd(icmp_fd) },
                                                unsafe { File::from_raw_fd(scheme_fd) })));

    let mut event_queue =
        EventQueue::<(), Error>::new()
            .map_err(|e| Error::from_io_error(e, "failed to create event queue"))?;

    let icmpd_ = icmpd.clone();

    event_queue
        .add(icmp_fd, move |_fd| {
            if let Err(err) = icmpd_.borrow_mut().on_icmp_packet() {
                if err.is_unrecoverable() {
                    return Err(err);
                } else {
                    println!("icmpd: network error: {}", err);
                }
            }
            Ok(None)
        })
        .map_err(|e| Error::from_io_error(e, "failed to listen to events on ip:1"))?;

    event_queue
        .add(scheme_fd, move |_fd| {
            if let Err(err) = icmpd.borrow_mut().on_scheme_event() {
                if err.is_unrecoverable() {
                    return Err(err);
                } else {
                    println!("icmpd: scheme error: {}", err);
                }
            }
            Ok(None)
        })
        .map_err(|e| Error::from_io_error(e, "failed to listen to events on icmp"))?;

    event_queue.run()
}

fn main() {
    if let Err(err) = run() {
        println!("icmpd: {}", err);
        process::exit(1);
    }
    process::exit(0);
}
