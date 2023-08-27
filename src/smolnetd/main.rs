#![feature(drain_filter)]

extern crate event;
#[macro_use]
extern crate log;
extern crate netutils;
extern crate redox_netstack;
extern crate smoltcp;
extern crate syscall;
extern crate byteorder;

use std::cell::RefCell;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::process;
use std::rc::Rc;

use redox_netstack::error::{Error, Result};
use redox_netstack::logger;
use event::EventQueue;
use scheme::Smolnetd;

mod buffer_pool;
mod device;
mod port_set;
mod scheme;

fn run(daemon: redox_daemon::Daemon) -> Result<()> {
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

    trace!("opening :icmp");
    let icmp_fd = syscall::open(":icmp", O_RDWR | O_CREAT | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open :icmp"))?
        as RawFd;

    trace!("opening :netcfg");
    let netcfg_fd = syscall::open(":netcfg", O_RDWR | O_CREAT | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open :netcfg"))?
        as RawFd;

    let time_path = format!("time:{}", syscall::CLOCK_MONOTONIC);
    let time_fd = syscall::open(&time_path, syscall::O_RDWR)
        .map_err(|e| Error::from_syscall_error(e, "failed to open time:"))?
        as RawFd;

    let (network_file, ip_file, time_file, udp_file, tcp_file, icmp_file, netcfg_file) = unsafe {
        (
            File::from_raw_fd(network_fd),
            File::from_raw_fd(ip_fd),
            File::from_raw_fd(time_fd),
            File::from_raw_fd(udp_fd),
            File::from_raw_fd(tcp_fd),
            File::from_raw_fd(icmp_fd),
            File::from_raw_fd(netcfg_fd),
        )
    };

    let smolnetd = Rc::new(RefCell::new(Smolnetd::new(
        network_file,
        ip_file,
        udp_file,
        tcp_file,
        icmp_file,
        time_file,
        netcfg_file,
    )));

    let mut event_queue = EventQueue::<(), Error>::new()
        .map_err(|e| Error::from_io_error(e, "failed to create event queue"))?;

    syscall::setrens(0, 0).expect("smolnetd: failed to enter null namespace");

    daemon.ready().expect("smolnetd: failed to notify parent");

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(network_fd, move |_| {
            smolnetd_.borrow_mut().on_network_scheme_event()
        })
        .map_err(|e| Error::from_io_error(e, "failed to listen to network events"))?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(ip_fd, move |_| smolnetd_.borrow_mut().on_ip_scheme_event())
        .map_err(|e| Error::from_io_error(e, "failed to listen to ip events"))?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(udp_fd, move |_| {
            smolnetd_.borrow_mut().on_udp_scheme_event()
        })
        .map_err(|e| Error::from_io_error(e, "failed to listen to udp events"))?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(tcp_fd, move |_| {
            smolnetd_.borrow_mut().on_tcp_scheme_event()
        })
        .map_err(|e| Error::from_io_error(e, "failed to listen to tcp events"))?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(icmp_fd, move |_| {
            smolnetd_.borrow_mut().on_icmp_scheme_event()
        })
        .map_err(|e| Error::from_io_error(e, "failed to listen to icmp events"))?;

    let smolnetd_ = Rc::clone(&smolnetd);

    event_queue
        .add(time_fd, move |_| smolnetd_.borrow_mut().on_time_event())
        .map_err(|e| Error::from_io_error(e, "failed to listen to time events"))?;

    event_queue
        .add(netcfg_fd, move |_| {
            smolnetd.borrow_mut().on_netcfg_scheme_event()
        })
        .map_err(|e| Error::from_io_error(e, "failed to listen to netcfg events"))?;

    event_queue.trigger_all(event::Event {
        fd: 0,
        flags: EventFlags::empty()
    })?;

    event_queue.run()
}

fn main() {
    redox_daemon::Daemon::new(move |daemon| {
        logger::init_logger();

        if let Err(err) = run(daemon) {
            error!("smoltcpd: {}", err);
            process::exit(1);
        }
        process::exit(0);
    }).expect("smoltcp: failed to daemonize");
}
