#![feature(drain_filter)]

extern crate event;
#[macro_use]
extern crate log;
extern crate netutils;
extern crate smoltcp;
extern crate syscall;

use std::cell::RefCell;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::process;
use std::rc::Rc;

use error::{Error, Result};
use event::EventQueue;
use scheme::Smolnetd;

mod buffer_pool;
mod device;
mod error;
mod logger;
mod scheme;
mod port_set;

fn run() -> Result<()> {
    use syscall::flag::*;

    trace!("opening network:");
    let network_fd = syscall::open("network:", O_RDWR | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open network:"))?
        as RawFd;

    trace!("opening :ip");
    let ip_fd = syscall::open(":ip", O_RDWR | O_CREAT | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open :ip"))? as RawFd;

    trace!("opening :udp");
    let udp_fd = syscall::open(":udp", O_RDWR | O_CREAT | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open :udp"))?
        as RawFd;

    trace!("opening :tcp");
    let tcp_fd = syscall::open(":tcp", O_RDWR | O_CREAT | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open :tcp"))?
        as RawFd;

    let time_path = format!("time:{}", syscall::CLOCK_MONOTONIC);
    let time_fd = syscall::open(&time_path, syscall::O_RDWR)
        .map_err(|e| Error::from_syscall_error(e, "failed to open time:"))?
        as RawFd;

    let (network_file, ip_file, time_file, udp_file, tcp_file) = unsafe {
        (
            File::from_raw_fd(network_fd),
            File::from_raw_fd(ip_fd),
            File::from_raw_fd(time_fd),
            File::from_raw_fd(udp_fd),
            File::from_raw_fd(tcp_fd),
        )
    };

    let smolnetd = Rc::new(RefCell::new(Smolnetd::new(
        network_file,
        ip_file,
        udp_file,
        tcp_file,
        time_file,
    )));

    let mut event_queue = EventQueue::<(), Error>::new()
        .map_err(|e| Error::from_io_error(e, "failed to create event queue"))?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(network_fd, move |_| {
            smolnetd_.borrow_mut().on_network_scheme_event()
        })
        .map_err(|e| {
            Error::from_io_error(e, "failed to listen to network events")
        })?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(ip_fd, move |_| smolnetd_.borrow_mut().on_ip_scheme_event())
        .map_err(|e| Error::from_io_error(e, "failed to listen to ip events"))?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(
            udp_fd,
            move |_| smolnetd_.borrow_mut().on_udp_scheme_event(),
        )
        .map_err(|e| {
            Error::from_io_error(e, "failed to listen to udp events")
        })?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(
            tcp_fd,
            move |_| smolnetd_.borrow_mut().on_tcp_scheme_event(),
        )
        .map_err(|e| {
            Error::from_io_error(e, "failed to listen to tcp events")
        })?;

    event_queue
        .add(time_fd, move |_| smolnetd.borrow_mut().on_time_event())
        .map_err(|e| {
            Error::from_io_error(e, "failed to listen to time events")
        })?;

    event_queue.trigger_all(0)?;

    event_queue.run()
}

fn main() {
    if unsafe { syscall::clone(0).unwrap() } == 0 {
        logger::init_logger();

        if let Err(err) = run() {
            error!("smoltcpd: {}", err);
            process::exit(1);
        }
    }
}
