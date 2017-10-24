use smoltcp::iface::{ArpCache, SliceArpCache};
use smoltcp::wire::{EthernetAddress, IpAddress};
use std::collections::BTreeSet;
use std::iter::FromIterator;

//TODO: move to EthernetAddress::LOCAL (?)
pub const LOOPBACK_HWADDR: EthernetAddress = EthernetAddress([0; 6]);

pub struct LoArpCache {
    arp_cache: SliceArpCache<'static>,
    local_ips: BTreeSet<IpAddress>,
}

impl LoArpCache {
    pub fn new<I>(local_ips: I) -> LoArpCache
    where
        I: IntoIterator<Item = IpAddress>,
    {
        LoArpCache {
            arp_cache: SliceArpCache::new(vec![Default::default(); 16]),
            local_ips: BTreeSet::from_iter(local_ips),
        }
    }
}

impl ArpCache for LoArpCache {
    fn fill(&mut self, protocol_addr: &IpAddress, hardware_addr: &EthernetAddress) {
        self.arp_cache.fill(protocol_addr, hardware_addr)
    }

    fn lookup(&mut self, protocol_addr: &IpAddress) -> Option<EthernetAddress> {
        //TODO: use IpAddress::is_loopback
        if let &IpAddress::Ipv4(ipv4_addr) = protocol_addr {
            if ipv4_addr.is_loopback() {
                return Some(LOOPBACK_HWADDR);
            }
        }

        if self.local_ips.contains(protocol_addr) {
            return Some(LOOPBACK_HWADDR);
        }

        self.arp_cache.lookup(protocol_addr)
    }
}
