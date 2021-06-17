#![feature(nll)]

extern crate dns_parser;
extern crate event;
#[macro_use]
extern crate log;
extern crate redox_netstack;
extern crate syscall;

use event::EventQueue;
use redox_netstack::error::{Error, Result};
use redox_netstack::logger;
use scheme::Dnsd;
use std::cell::RefCell;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::process;
use std::rc::Rc;

use syscall::{CloneFlags, EventFlags};

mod scheme;

fn run() -> Result<()> {
    use syscall::flag::*;

    let dns_fd = syscall::open(":dns", O_RDWR | O_CREAT | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open :dns"))?
        as RawFd;

    let time_path = format!("time:{}", syscall::CLOCK_MONOTONIC);
    let time_fd = syscall::open(&time_path, syscall::O_RDWR)
        .map_err(|e| Error::from_syscall_error(e, "failed to open time:"))?
        as RawFd;

    let nameserver_fd = syscall::open(
        "netcfg:resolv/nameserver",
        syscall::O_RDWR | syscall::O_CREAT | syscall::O_NONBLOCK,
    ).map_err(|e| Error::from_syscall_error(e, "failed to open nameserver:"))?
        as RawFd;

    let (dns_file, time_file) = unsafe {
        (
            File::from_raw_fd(dns_fd),
            File::from_raw_fd(time_fd),
        )
    };

    let mut event_queue = EventQueue::<(), Error>::new()
        .map_err(|e| Error::from_io_error(e, "failed to create event queue"))?;

    let dnsd = Rc::new(RefCell::new(Dnsd::new(dns_file, time_file, event_queue.file.as_raw_fd())));

    syscall::setrens(0, 0).expect("dnsd: failed to enter null namespace");

    let dnsd_ = Rc::clone(&dnsd);

    event_queue
        .add(dns_fd, move |_| dnsd_.borrow_mut().on_dns_file_event())
        .map_err(|e| Error::from_io_error(e, "failed to listen to time events"))?;

    let dnsd_ = Rc::clone(&dnsd);

    event_queue
        .add(nameserver_fd, move |_| dnsd_.borrow_mut().on_nameserver_event())
        .map_err(|e| Error::from_io_error(e, "failed to listen to nameserver"))?;

    let dnsd_ = Rc::clone(&dnsd);

    event_queue.set_default_callback(move |event| dnsd_.borrow_mut().on_unknown_fd_event(event.fd));

    event_queue
        .add(time_fd, move |_| dnsd.borrow_mut().on_time_event())
        .map_err(|e| Error::from_io_error(e, "failed to listen to time events"))?;

    event_queue.trigger_all(event::Event {
        fd: 0,
        flags: EventFlags::empty(),
    })?;

    event_queue.run()
}

fn main() {
    if unsafe { syscall::clone(CloneFlags::empty()).unwrap() } == 0 {
        logger::init_logger();
        if let Err(err) = run() {
            error!("dnsd: {}", err);
            process::exit(1);
        }
    }
}
