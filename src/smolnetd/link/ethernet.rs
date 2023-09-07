use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::rc::Rc;

use smoltcp::storage::PacketMetadata;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol,
    EthernetRepr, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr,
};

use super::LinkDevice;

struct Neighbor {
    hardware_address: EthernetAddress,
    expires_at: Instant,
}

#[derive(Debug, Default)]
enum ArpState {
    #[default]
    Discovered,
    Discovering {
        target: Ipv4Address,
        tries: u32,
        silent_until: Instant,
    },
}

type PacketBuffer = smoltcp::storage::PacketBuffer<'static, IpAddress>;

const EMPTY_MAC: EthernetAddress = EthernetAddress([0; 6]);

pub struct EthernetLink {
    name: Rc<str>,
    neighbor_cache: BTreeMap<IpAddress, Neighbor>,
    arp_state: ArpState,
    waiting_packets: PacketBuffer,
    input_buffer: Vec<u8>,
    output_buffer: Vec<u8>,
    network_file: File,
    hardware_address: Option<EthernetAddress>,
    ip_address: Option<Ipv4Cidr>,
}

impl EthernetLink {
    // TODO: Review these constants
    const MAX_WAITING_PACKET_COUNT: usize = 10;
    const MTU: usize = 1500;
    const WAITING_PACKET_BUFFER_SIZE: usize = Self::MTU * Self::MAX_WAITING_PACKET_COUNT;

    const NEIGHBOR_LIVE_TIME: Duration = Duration::from_secs(60);
    const ARP_SILENCE_TIME: Duration = Duration::from_secs(1);

    pub fn new(name: &str, network_file: File) -> Self {
        let waiting_packets = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; Self::MAX_WAITING_PACKET_COUNT],
            vec![0u8; Self::WAITING_PACKET_BUFFER_SIZE],
        );

        Self {
            name: name.into(),
            network_file,
            waiting_packets,
            hardware_address: None,
            ip_address: None,
            input_buffer: vec![0u8; Self::MTU],
            output_buffer: Vec::with_capacity(Self::MTU),
            arp_state: Default::default(),
            neighbor_cache: Default::default(),
        }
    }

    fn send_to<F>(&mut self, dst: EthernetAddress, size: usize, f: F, proto: EthernetProtocol)
    where
        F: FnOnce(&mut [u8]),
    {
        let Some(hardware_address) = self.hardware_address else {
            return;
        };

        let repr = EthernetRepr {
            src_addr: hardware_address,
            dst_addr: dst,
            ethertype: proto,
        };

        self.output_buffer.clear();
        self.output_buffer.resize(repr.buffer_len() + size, 0);
        let mut frame = EthernetFrame::new_unchecked(&mut self.output_buffer);
        repr.emit(&mut frame);

        f(frame.payload_mut());

        if let Err(_) = self.network_file.write_all(&self.output_buffer) {
            error!(
                "Dropped outboud packet on {} (failed to write to network file)",
                self.name
            )
        }
    }

    fn process_arp(&mut self, packet: &[u8], now: Instant) {
        let Some(hardware_address) = self.hardware_address else {
            return;
        };

        let Some(ip_addr) = self.ip_address else {
            return;
        };

        let Ok(repr) = ArpPacket::new_checked(packet).and_then(|packet| ArpRepr::parse(&packet)) else {
            debug!("Dropped incomming arp packet on {} (Malformed)", self.name);
            return;
        };

        match repr {
            ArpRepr::EthernetIpv4 {
                operation,
                source_hardware_addr,
                source_protocol_addr,
                target_hardware_addr,
                target_protocol_addr,
            } => {
                if hardware_address != target_hardware_addr {
                    // Only process packet that are for us
                    return;
                }

                if let ArpOperation::Unknown(_) = operation {
                    return;
                }

                if !source_hardware_addr.is_unicast() || !source_protocol_addr.is_unicast() {
                    return;
                }

                if !ip_addr.contains_addr(&target_protocol_addr) {
                    return;
                }

                self.neighbor_cache.insert(
                    IpAddress::Ipv4(source_protocol_addr),
                    Neighbor {
                        hardware_address: source_hardware_addr,
                        expires_at: now + Self::NEIGHBOR_LIVE_TIME,
                    },
                );

                if let ArpOperation::Request = operation {
                    let response = ArpRepr::EthernetIpv4 {
                        operation: ArpOperation::Reply,
                        source_hardware_addr: hardware_address,
                        source_protocol_addr: ip_addr.address(),
                        target_hardware_addr: source_hardware_addr,
                        target_protocol_addr: source_protocol_addr,
                    };

                    self.send_to(
                        source_hardware_addr,
                        response.buffer_len(),
                        |buf| response.emit(&mut ArpPacket::new_unchecked(buf)),
                        EthernetProtocol::Arp,
                    );
                }
                self.check_waiting_packets(source_protocol_addr, source_hardware_addr, now);
            }
            _ => {}
        }
    }

    fn check_waiting_packets(&mut self, ip: Ipv4Address, mac: EthernetAddress, now: Instant) {
        let mut waiting_packets =
            std::mem::replace(&mut self.waiting_packets, PacketBuffer::new(vec![], vec![]));
        loop {
            match waiting_packets.peek() {
                Ok((IpAddress::Ipv4(dst), _)) if dst == &ip => {}
                Ok((IpAddress::Ipv4(dst), _)) => {
                    self.arp_state = ArpState::Discovering {
                        target: *dst,
                        tries: 0,
                        silent_until: Instant::ZERO,
                    };
                    self.send_arp(now);
                    break;
                }
                Err(_) => {
                    self.arp_state = ArpState::Discovered;
                    break;
                }
            }

            let (_, packet) = waiting_packets.dequeue().unwrap();
            self.send_to(
                mac,
                packet.len(),
                |buf| buf.copy_from_slice(packet),
                EthernetProtocol::Ipv4,
            );
        }

        self.waiting_packets = waiting_packets;
    }

    fn drop_waiting_packets(&mut self, ip: Ipv4Address, now: Instant) {
        loop {
            match self.waiting_packets.peek() {
                Ok((IpAddress::Ipv4(dst), _)) if dst == &ip => {}
                Ok((IpAddress::Ipv4(dst), _)) => {
                    self.arp_state = ArpState::Discovering {
                        target: *dst,
                        tries: 0,
                        silent_until: Instant::ZERO,
                    };

                    self.send_arp(now);

                    return;
                }
                Err(_) => {
                    self.arp_state = ArpState::Discovered;
                    return;
                }
            }

            let _ = self.waiting_packets.dequeue();
            debug!(
                "Dropped packet on {} because neighbor was not found",
                self.name
            )
        }
    }

    fn handle_missing_neighbor(&mut self, next_hop: IpAddress, packet: &[u8], now: Instant) {
        let Ok(buf) = self.waiting_packets.enqueue(packet.len(), next_hop) else {
            warn!("Dropped packet on {} because waiting queue was full", self.name);
            return;
        };
        buf.copy_from_slice(packet);

        let IpAddress::Ipv4(next_hop) = next_hop;
        if let ArpState::Discovered = self.arp_state {
            self.arp_state = ArpState::Discovering {
                target: next_hop,
                tries: 0,
                silent_until: Instant::ZERO,
            };

            self.send_arp(now)
        }
    }

    fn send_arp(&mut self, now: Instant) {
        let Some(hardware_address) = self.hardware_address else {
            return;
        };

        let Some(ip_address) = self.ip_address else {
            return;
        };

        match self.arp_state {
            ArpState::Discovered => {}
            ArpState::Discovering { silent_until, .. } if silent_until > now => {}
            ArpState::Discovering { target, tries, .. } if tries >= 3 => {
                self.drop_waiting_packets(target, now)
            }
            ArpState::Discovering {
                target,
                ref mut tries,
                ref mut silent_until,
            } => {
                let arp_repr = ArpRepr::EthernetIpv4 {
                    operation: ArpOperation::Request,
                    source_hardware_addr: hardware_address,
                    source_protocol_addr: ip_address.address(),
                    target_hardware_addr: EthernetAddress::BROADCAST,
                    target_protocol_addr: target,
                };

                *tries += 1;
                *silent_until = now + Self::ARP_SILENCE_TIME;

                self.send_to(
                    EthernetAddress::BROADCAST,
                    arp_repr.buffer_len(),
                    |buf| arp_repr.emit(&mut ArpPacket::new_unchecked(buf)),
                    EthernetProtocol::Arp,
                );
            }
        }
    }
}

impl LinkDevice for EthernetLink {
    fn send(&mut self, next_hop: IpAddress, packet: &[u8], now: Instant) {
        let local_broadcast = match self.ip_address.and_then(|cidr| cidr.broadcast()) {
            Some(addr) => IpAddress::Ipv4(addr) == next_hop,
            None => false,
        };

        if local_broadcast || next_hop.is_broadcast() {
            self.send_to(
                EthernetAddress::BROADCAST,
                packet.len(),
                |buf| buf.copy_from_slice(packet),
                EthernetProtocol::Ipv4,
            );
            return;
        }

        match self.neighbor_cache.entry(next_hop) {
            Entry::Vacant(_) => self.handle_missing_neighbor(next_hop, packet, now),
            Entry::Occupied(e) => {
                if e.get().expires_at < now {
                    e.remove();
                    self.handle_missing_neighbor(next_hop, packet, now)
                } else {
                    let mac = e.get().hardware_address;
                    self.send_to(
                        mac,
                        packet.len(),
                        |buf| buf.copy_from_slice(packet),
                        EthernetProtocol::Ipv4,
                    )
                }
            }
        }
    }

    fn recv(&mut self, now: Instant) -> Option<&[u8]> {
        let Some(hardware_address) = self.hardware_address else {
            return None;
        };

        let mut input_buffer = std::mem::replace(&mut self.input_buffer, Vec::new());
        loop {
            if let Err(e) = self.network_file.read(&mut input_buffer) {
                if e.kind() != ErrorKind::WouldBlock {
                    error!("Failed to read ethernet device on link {}", self.name);
                } else {
                    // No packet to read but we check if we have arp to send
                    self.send_arp(now);
                }
                self.input_buffer = input_buffer;
                return None;
            }
            let packet = EthernetFrame::new_unchecked(&input_buffer[..]);
            let Ok(repr) = EthernetRepr::parse(&packet) else {
                debug!("Dropped incomming frame on {} (Malformed)", self.name);
                continue;
            };

            // We let EMPTY_MAC pass because somehow this is the mac used when net=redir is used
            if !repr.dst_addr.is_broadcast()
                && repr.dst_addr != EMPTY_MAC
                && repr.dst_addr != hardware_address
            {
                // Drop packets which are not for us
                continue;
            }

            match repr.ethertype {
                EthernetProtocol::Ipv4 => {
                    self.input_buffer = input_buffer;
                    return Some(EthernetFrame::new_unchecked(&self.input_buffer[..]).payload());
                }
                EthernetProtocol::Arp => self.process_arp(packet.payload(), now),
                _ => continue,
            }
        }
    }

    fn name(&self) -> &Rc<str> {
        &self.name
    }

    fn can_recv(&self) -> bool {
        // We don't buffer any packets so we can't receive immediatly
        false
    }

    fn mac_address(&self) -> Option<EthernetAddress> {
        self.hardware_address
    }

    fn set_mac_address(&mut self, addr: EthernetAddress) {
        self.hardware_address = Some(addr)
    }

    fn ip_address(&self) -> Option<IpCidr> {
        Some(IpCidr::Ipv4(self.ip_address?))
    }

    fn set_ip_address(&mut self, addr: IpCidr) {
        let IpCidr::Ipv4(addr) = addr;
        self.ip_address = Some(addr);
    }
}
