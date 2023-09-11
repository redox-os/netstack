use std::cell::RefCell;
use std::rc::Rc;

use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::storage::PacketMetadata;
use smoltcp::time::Instant;
use smoltcp::wire::IpAddress;

use self::route_table::RouteTable;
use crate::link::DeviceList;
use crate::scheme::Smolnetd;

pub mod route_table;

pub type PacketBuffer = smoltcp::storage::PacketBuffer<'static, ()>;

pub struct Router {
    rx_buffer: PacketBuffer,
    tx_buffer: PacketBuffer,
    devices: Rc<RefCell<DeviceList>>,
    route_table: Rc<RefCell<RouteTable>>,
}

impl Router {
    pub fn new(devices: Rc<RefCell<DeviceList>>, route_table: Rc<RefCell<RouteTable>>) -> Self {
        let rx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
            vec![0u8; Router::MTU * Smolnetd::SOCKET_BUFFER_SIZE],
        );
        let tx_buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
            vec![0u8; Router::MTU * Smolnetd::SOCKET_BUFFER_SIZE],
        );
        Self {
            rx_buffer,
            tx_buffer,
            devices,
            route_table,
        }
    }

    pub const MTU: usize = 1486;

    pub fn can_recv(&self) -> bool {
        let mut can_recv = false;
        for dev in self.devices.borrow().iter() {
            can_recv |= dev.can_recv();
        }
        can_recv
    }

    pub fn poll(&mut self, now: Instant) {
        for dev in self.devices.borrow_mut().iter_mut() {
            if self.rx_buffer.is_full() {
                break;
            }

            loop {
                if self.rx_buffer.is_full() {
                    break;
                }

                let Some(buf) = dev.recv(now) else {
                    break;
                };

                self.rx_buffer
                    .enqueue(buf.len(), ())
                    .expect("We checked if it was full")
                    .copy_from_slice(buf);
            }
        }
    }

    pub fn dispatch(&mut self, now: Instant) {
        while let Ok(((), packet)) = self.tx_buffer.dequeue() {
            if let Ok(mut packet) = smoltcp::wire::Ipv4Packet::new_checked(packet) {
                let dst_addr = IpAddress::Ipv4(packet.dst_addr());
                if packet.dst_addr().is_broadcast() {
                    let buf = packet.into_inner();
                    for dev in self.devices.borrow_mut().iter_mut() {
                        dev.send(dst_addr, buf, now)
                    }
                } else {
                    let route_table = self.route_table.borrow();
                    let Some(rule) = route_table.lookup_rule(&dst_addr) else {
                        warn!("No route found for destination: {}", dst_addr);
                        continue;
                    };

                    let next_hop = match rule.via {
                        Some(via) => via,
                        None => dst_addr,
                    };

                    let mut devices = self.devices.borrow_mut();
                    let Some(dev) = devices.get_mut(&rule.dev) else {
                        warn!("Device {} not found", rule.dev);
                        // TODO: Remove route if device doesn't exist anymore ?
                        continue;
                    };

                    let IpAddress::Ipv4(src) = rule.src;
                    if src != packet.src_addr() {
                        packet.set_src_addr(src);
                        packet.fill_checksum()
                    }

                    dev.send(next_hop, packet.into_inner(), now);
                }
            }
        }
    }
}

impl Device for Router {
    type RxToken<'a> = RxToken<'a>;

    type TxToken<'a> = TxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_buffer.is_empty() || self.tx_buffer.is_full() {
            None
        } else {
            Some((
                RxToken {
                    rx_buffer: &mut self.rx_buffer,
                },
                TxToken {
                    tx_buffer: &mut self.tx_buffer,
                },
            ))
        }
    }

    fn transmit(&mut self, _timestamp: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        if self.tx_buffer.is_full() {
            None
        } else {
            Some(TxToken {
                tx_buffer: &mut self.tx_buffer,
            })
        }
    }

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = Router::MTU;
        caps.max_burst_size = Some(Smolnetd::SOCKET_BUFFER_SIZE);
        caps
    }
}

pub struct TxToken<'a> {
    tx_buffer: &'a mut PacketBuffer,
}

impl smoltcp::phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(self
            .tx_buffer
            .enqueue(len, ())
            .expect("This was checked before creating the TxToken"))
    }
}

pub struct RxToken<'a> {
    rx_buffer: &'a mut PacketBuffer,
}

impl<'a> smoltcp::phy::RxToken for RxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let ((), buf) = self
            .rx_buffer
            .dequeue()
            .expect("This was checked before creating the RxToken");

        f(buf)
    }
}
