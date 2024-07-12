#[macro_use]
extern crate log;

use anyhow::{Error, Result, Context};
use event::EventQueue;
use ioslice::IoSlice;
use libredox::Fd;
use redox_netstack::logger;
use scheme::Dnsd;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::process;

mod scheme;

fn run(daemon: redox_daemon::Daemon) -> Result<()> {
    use libredox::flag::*;

    let dns_fd = Fd::open(":dns", O_RDWR | O_CREAT | O_NONBLOCK, 0)
        .context("failed to open :dns")?;

    let time_path = format!("/scheme/time/{}", CLOCK_MONOTONIC);
    let time_fd = Fd::open(&time_path, O_RDWR, 0)
        .context("failed to open time")?;

    let nameserver_fd = Fd::open(
        "/scheme/netcfg/resolv/nameserver",
        O_RDWR | O_CREAT | O_NONBLOCK,
        0,
    ).context("failed to open nameserver")?;

    let event_queue = EventQueue::<EventSource>::new()
        .context("failed to create event queue")?;

    event_queue
        .subscribe(dns_fd.raw(), EventSource::DnsScheme, event::EventFlags::READ)
        .context("failed to listen to time events")?;
    event_queue
        .subscribe(nameserver_fd.raw(), EventSource::NameserverScheme, event::EventFlags::READ)
        .context("failed to listen to nameserver socket events")?;
    event_queue
        .subscribe(time_fd.raw(), EventSource::Timer, event::EventFlags::READ)
        .context("failed to listen to timer events")?;

    let (dns_file, time_file) = unsafe {
        (
            File::from_raw_fd(dns_fd.into_raw() as RawFd),
            File::from_raw_fd(time_fd.into_raw() as RawFd),
        )
    };

    let mut dnsd = Dnsd::new(dns_file, time_file, &event_queue);

    let new_ns = libredox::call::mkns(&[IoSlice::new(b"dns")])
        .expect("dnsd: failed to create namespace");
    libredox::call::setrens(new_ns, new_ns).expect("dnsd: failed to enter namespace");

    daemon.ready().expect("dnsd: failed to notify parent");

    for event_res in event_queue.iter() {
        let event = event_res.context("failed to read from event queue")?;
        match event.user_data {
            EventSource::DnsScheme => if !dnsd.on_dns_file_event()? {
                break
            },
            EventSource::NameserverScheme => dnsd.on_nameserver_event()?,
            EventSource::Timer => dnsd.on_time_event()?,
            EventSource::Other => dnsd.on_unknown_fd_event(event.fd as RawFd)?,
        }
    }
    Ok(())
}

fn main() {
    redox_daemon::Daemon::new(move |daemon| {
        logger::init_logger("dnsd");
        if let Err(err) = run(daemon) {
            error!("dnsd: {}", err);
            process::exit(1);
        }
        process::exit(0);
    }).expect("dnsd: failed to daemonize");
}

event::user_data! {
    enum EventSource {
        DnsScheme,
        NameserverScheme,
        Timer,
        Other,
    }
}
