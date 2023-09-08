pub mod loopback;
pub mod ethernet;

use std::rc::Rc;

use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, EthernetAddress, IpCidr};

/// Represent a link layer device (eth0, loopback...)
pub trait LinkDevice {

    /// Send the given packet to the machine with the `next_hop` ip address
    /// This method cannot fail so it's the implementor responsability
    /// to buffer packets which can't be sent immediatly or decide to
    /// drop them if necessary
    fn send(&mut self, next_hop: IpAddress, packet: &[u8], now: Instant);

    /// Returns None if nothing is received.
    /// Returns an Ip packet otherwise
    fn recv(&mut self, now: Instant) -> Option<&[u8]>;

    /// Returns the LinkDevice display name used to refer to it and for lookups
    fn name(&self) -> &Rc<str>;

    /// Returns wether this device have packets pending
    fn can_recv(&self) -> bool;

    fn mac_address(&self) -> Option<EthernetAddress>;
    fn set_mac_address(&mut self, addr: EthernetAddress);

    fn ip_address(&self) -> Option<IpCidr>;
    fn set_ip_address(&mut self, addr: IpCidr);
}

#[derive(Default)]
pub struct DeviceList {
    inner: Vec<Box<dyn LinkDevice>>,
}

impl DeviceList {
    pub fn push<T: LinkDevice + 'static>(&mut self, dev: T) {
        self.inner.push(Box::new(dev))
    }

    pub fn get(&self, device_name: &str) -> Option<&dyn LinkDevice> {
        self.inner
            .iter()
            .find(|dev| dev.name().as_ref() == device_name)
            .map(|device| device.as_ref())
    }

    pub fn get_mut(&mut self, device_name: &str) -> Option<&mut (dyn LinkDevice + 'static)> {
        self.inner
            .iter_mut()
            .find(|dev| dev.name().as_ref() == device_name)
            .map(|device| device.as_mut())
    }

    pub fn iter(&self) -> impl Iterator<Item = &(dyn LinkDevice + 'static)> {
        self.inner.iter().map(|b| b.as_ref())
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (dyn LinkDevice + 'static)> {
        self.inner.iter_mut().map(|b| b.as_mut())
    }
}
