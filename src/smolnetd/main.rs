extern crate event;
#[macro_use]
extern crate log;
extern crate byteorder;
extern crate netutils;
extern crate redox_netstack;
extern crate smoltcp;
extern crate syscall;

use std::cell::RefCell;
use std::fs::File;
use std::os::unix::io::{FromRawFd, RawFd};
use std::process;
use std::rc::Rc;

use event::{EventQueue, EventFlags};
use libredox::Fd;
use libredox::flag::{O_RDWR, O_NONBLOCK, O_CREAT};
use anyhow::{Result, anyhow, bail, Context};

use redox_netstack::logger;
use scheme::Smolnetd;
use smoltcp::wire::EthernetAddress;

mod buffer_pool;
mod link;
mod port_set;
mod router;
mod scheme;

fn get_network_adapter() -> Result<String> {
    use std::fs;

    let mut adapters = vec![];

    for entry_res in fs::read_dir("/scheme")? {
        let Ok(entry) = entry_res else {
            continue;
        };

        let Ok(scheme) = entry.file_name().into_string() else {
            continue;
        };

        if !scheme.starts_with("network") {
            continue;
        }

        adapters.push(scheme);
    }

    if adapters.is_empty() {
        bail!("no network adapter found");
    } else {
        let adapter = adapters.remove(0);
        if !adapters.is_empty() {
            // FIXME allow using multiple network adapters at the same time
            warn!("Multiple network adapters found. Only {adapter} will be used");
        }
        Ok(adapter)
    }
}

fn run(daemon: redox_daemon::Daemon) -> Result<()> {
    let adapter = get_network_adapter()?;
    trace!("opening {adapter}:");
    let network_fd = Fd::open(&format!("/scheme/{adapter}"), O_RDWR | O_NONBLOCK, 0)
        .map_err(|e| anyhow!("failed to open {adapter}: {e}"))?;

    let hardware_addr = std::fs::read(format!("/scheme/{adapter}/mac"))
        .map(|mac_address| EthernetAddress::from_bytes(&mac_address))
        .context("failed to get mac address from network adapter")?;

    trace!("opening :ip");
    let ip_fd = Fd::open(":ip", O_RDWR | O_CREAT | O_NONBLOCK, 0)
        .context("failed to open :ip")?;

    trace!("opening :udp");
    let udp_fd = Fd::open(":udp", O_RDWR | O_CREAT | O_NONBLOCK, 0)
        .context("failed to open :udp")?;

    trace!("opening :tcp");
    let tcp_fd = Fd::open(":tcp", O_RDWR | O_CREAT | O_NONBLOCK, 0)
        .context("failed to open :tcp")?;

    trace!("opening :icmp");
    let icmp_fd = Fd::open(":icmp", O_RDWR | O_CREAT | O_NONBLOCK, 0)
        .context("failed to open :icmp")?;

    trace!("opening :netcfg");
    let netcfg_fd = Fd::open(":netcfg", O_RDWR | O_CREAT | O_NONBLOCK, 0)
        .context("failed to open :netcfg")?;

    let time_path = format!("/scheme/time/{}", syscall::CLOCK_MONOTONIC);
    let time_fd = Fd::open(&time_path, O_RDWR, 0)
        .context("failed to open /scheme/time")?;

    event::user_data! {
        enum EventSource {
            Network,
            Time,
            IpScheme,
            UdpScheme,
            TcpScheme,
            IcmpScheme,
            NetcfgScheme,
        }
    }

    let event_queue = EventQueue::<EventSource>::new()
        .context("failed to create event queue")?;

    daemon.ready().expect("smolnetd: failed to notify parent");

    event_queue.subscribe(network_fd.raw(), EventSource::Network, EventFlags::READ)
        .context("failed to listen to network events")?;

    event_queue.subscribe(time_fd.raw(), EventSource::Time, EventFlags::READ)
        .context("failed to listen to timer events")?;

    event_queue.subscribe(ip_fd.raw(), EventSource::IpScheme, EventFlags::READ)
        .context("failed to listen to ip scheme events")?;

    event_queue.subscribe(udp_fd.raw(), EventSource::UdpScheme, EventFlags::READ)
        .context("failed to listen to udp scheme events")?;

    event_queue.subscribe(tcp_fd.raw(), EventSource::TcpScheme, EventFlags::READ)
        .context("failed to listen to tcp scheme events")?;

    event_queue.subscribe(icmp_fd.raw(), EventSource::IcmpScheme, EventFlags::READ)
        .context("failed to listen to icmp scheme events")?;

    event_queue.subscribe(netcfg_fd.raw(), EventSource::NetcfgScheme, EventFlags::READ)
        .context("failed to listen to netcfg scheme events")?;

    let mut smolnetd = Smolnetd::new(
        network_fd,
        hardware_addr,
        ip_fd,
        udp_fd,
        tcp_fd,
        icmp_fd,
        time_fd,
        netcfg_fd,
    );

    libredox::call::setrens(0, 0)
        .context("smolnetd: failed to enter null namespace")?;

    let all = {
        use EventSource::*;
        [Network, Time, IpScheme, UdpScheme, IcmpScheme, NetcfgScheme].map(Ok)
    };

    for event_res in all.into_iter().chain(event_queue.map(|r| r.map(|e| e.user_data))) {
        match event_res? {
            EventSource::Network => smolnetd.on_network_scheme_event()?,
            EventSource::Time => smolnetd.on_time_event()?,
            EventSource::IpScheme => smolnetd.on_ip_scheme_event()?,
            EventSource::UdpScheme => smolnetd.on_udp_scheme_event()?,
            EventSource::TcpScheme => smolnetd.on_tcp_scheme_event()?,
            EventSource::IcmpScheme => smolnetd.on_icmp_scheme_event()?,
            EventSource::NetcfgScheme => smolnetd.on_netcfg_scheme_event()?,
        }
    }
    Ok(())
}

fn main() {
    redox_daemon::Daemon::new(move |daemon| {
        logger::init_logger("smolnetd");

        if let Err(err) = run(daemon) {
            error!("smoltcpd: {}", err);
            process::exit(1);
        }
        process::exit(0);
    })
    .expect("smoltcp: failed to daemonize");
}
