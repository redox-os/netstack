extern crate event;
extern crate syscall;
extern crate netutils;

use error::{Result, Error, ParsingError};
use event::EventQueue;
use netutils::{Ipv4, Ipv4Header, Checksum, n16};
use packet::{Packet, MutPacket};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::{RawFd, FromRawFd};
use std::process;
use std::mem;

mod error;
mod packet;

const MAX_PACKET_SIZE: usize = 2048;

fn do_echo_response(in_ip_packet: &Ipv4,
                    in_icmp_packet: &Packet,
                    icmp_file: &mut File)
                    -> Result<()> {
    let mut ip_data = vec![0; in_icmp_packet.get_total_data_size()];
    {
        let mut out_icmp_packet =
            MutPacket::from_bytes(&mut ip_data)
                .map_err(|e| Error::from_parsing_error(e, "can't parse empty icmp header"))?;
        out_icmp_packet.set_echo_response();
        {
            let payload = out_icmp_packet.get_payload();
            let in_payload = in_icmp_packet.get_payload();
            if payload.len() != in_payload.len() {
                return Err(Error::from_parsing_error(ParsingError::NotEnoughData,
                                                     " can't copy icmp payload to echo response"));
            }
            //WARNING: copy_from_slice can panic if the slices' lengths are different
            payload.copy_from_slice(in_icmp_packet.get_payload());
        }
        out_icmp_packet.compute_checksum();
    }
    let out_ip_packet = Ipv4 {
        header: Ipv4Header {
            ver_hlen: 0x45,
            services: 0,
            len: n16::new((ip_data.len() + mem::size_of::<Ipv4Header>()) as u16),
            id: n16::new(0),
            flags_fragment: n16::new(0),
            ttl: in_ip_packet.header.ttl,
            proto: 1,
            checksum: Checksum { data: 0 },
            src: in_ip_packet.header.dst,
            dst: in_ip_packet.header.src,
        },
        options: Vec::new(),
        data: ip_data,
    };
    icmp_file
        .write(&out_ip_packet.to_bytes())
        .map_err(|e| Error::from_io_error(e, " can't send an echo response packet"))
        .map(|_| ())
}

fn on_icmp_packet(icmp_file: &mut File) -> Result<Option<()>> {
    let mut packet_buffer = [0; MAX_PACKET_SIZE];
    loop {
        let bytes_readed =
            icmp_file
                .read(&mut packet_buffer)
                .map_err(|e| Error::from_io_error(e, "failed to read a packet from ip:1"))?;
        if bytes_readed == 0 {
            break;
        }
        let ip_packet = Ipv4::from_bytes(&packet_buffer[..bytes_readed])
            .ok_or(Error::from_parsing_error(ParsingError::NotEnoughData,
                                             "failed to parse ip header"))?;
        let icmp_packet =
            Packet::from_bytes(&ip_packet.data)
                .map_err(|e| Error::from_parsing_error(e, "failed to parse ICMP packet"))?;

        if icmp_packet.is_echo_request() {
            do_echo_response(&ip_packet, &icmp_packet, icmp_file)?;
        }
    }
    Ok(None)
}

fn run() -> Result<()> {
    use syscall::flag::*;

    let icmp_fd = syscall::open("ip:1", O_RDWR | O_NONBLOCK)
        .map_err(|e| Error::from_syscall_error(e, "failed to open ip:1"))?;

    if unsafe { syscall::clone(0).unwrap() } != 0 {
        return Ok(());
    }

    let mut event_queue =
        EventQueue::<(), Error>::new()
            .map_err(|e| Error::from_io_error(e, "failed to create event queue"))?;
    let mut icmp_file = unsafe { File::from_raw_fd(icmp_fd as RawFd) };
    event_queue
        .add(icmp_fd as RawFd,
             move |_fd| -> Result<Option<()>> { on_icmp_packet(&mut icmp_file) })
        .map_err(|e| Error::from_io_error(e, "failed to listen to events on ip:1"))?;
    event_queue.run()
}

fn main() {
    match run() {
        Err(err) => println!("icmpd: {}", err),
        _ => {}
    }
    process::exit(0);
}
