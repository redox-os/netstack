use std::rc::Rc;

use smoltcp::storage::PacketMetadata;
use smoltcp::time::Instant;

use crate::scheme::Smolnetd;

use super::LinkDevice;

pub type PacketBuffer = smoltcp::storage::PacketBuffer<'static, ()>;

pub struct LoopbackDevice {
    name: Rc<str>,
    buffer: PacketBuffer,
}

impl Default for LoopbackDevice {
    fn default() -> Self {
        let buffer = PacketBuffer::new(
            vec![PacketMetadata::EMPTY; Smolnetd::SOCKET_BUFFER_SIZE],
            vec![0u8; 1500 * Smolnetd::SOCKET_BUFFER_SIZE],
        );
        LoopbackDevice {
            name: "loopback".into(),
            buffer,
        }
    }
}

impl LinkDevice for LoopbackDevice {
    fn send(&mut self, _next_hop: smoltcp::wire::IpAddress, packet: &[u8], _now: Instant) {
        match self.buffer.enqueue(packet.len(), ()) {
            Err(_) => warn!("loopback dropped packet because buffer was full"),
            Ok(buf) => buf.copy_from_slice(packet),
        }
    }

    fn recv(&mut self, _now: Instant) -> Option<&[u8]> {
        self.buffer.dequeue().ok().map(|((), buf)| &*buf)
    }

    fn name(&self) -> &std::rc::Rc<str> {
        &self.name
    }

    fn can_recv(&self) -> bool {
        !self.buffer.is_empty()
    }

    fn mac_address(&self) -> Option<smoltcp::wire::EthernetAddress> {
        None
    }

    fn set_mac_address(&mut self, _addr: smoltcp::wire::EthernetAddress) {
    }

    fn ip_address(&self) -> Option<smoltcp::wire::IpCidr> {
        Some("127.0.0.1/8".parse().unwrap())
    }

    fn set_ip_address(&mut self, _addr: smoltcp::wire::IpCidr) {
        todo!()
    }


}
