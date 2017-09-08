use error::Result;
use std::rc::Rc;
use std::fs::File;
use std::cell::RefCell;
use std::time::Instant;
use std::io::{Read, Write};
use syscall::SchemeMut;
use syscall;
use smoltcp;

struct NetworkDevice {
    network_file: Rc<RefCell<File>>,
}

impl NetworkDevice {
    const MTU: usize = 1520;

    pub fn new(network_file: File) -> NetworkDevice {
        NetworkDevice {
            network_file: Rc::new(RefCell::new(network_file)),
        }
    }
}

struct TxBuffer {
    buffer: Vec<u8>,
    network_file: Rc<RefCell<File>>,
}

impl AsRef<[u8]> for TxBuffer {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

impl AsMut<[u8]> for TxBuffer {
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl Drop for TxBuffer {
    fn drop(&mut self) {
        let _ = self.network_file.borrow_mut().write(&self.buffer);
    }
}

impl smoltcp::phy::Device for NetworkDevice {
    type RxBuffer = Vec<u8>;
    type TxBuffer = TxBuffer;

    fn limits(&self) -> smoltcp::phy::DeviceLimits {
        let mut limits = smoltcp::phy::DeviceLimits::default();
        limits.max_transmission_unit = Self::MTU;
        limits.max_burst_size = Some(1);
        limits
    }

    fn receive(&mut self, _timestamp: u64) -> smoltcp::Result<Self::RxBuffer> {
        let mut buffer = Vec::with_capacity(65536);
        if let Ok(count) = self.network_file.borrow_mut().read(&mut buffer) {
            if count == 0 {
                return Err(smoltcp::Error::Exhausted);
            }
            buffer.resize(count, 0);
            Ok(buffer)
        } else {
            Err(smoltcp::Error::Exhausted)
        }
    }

    fn transmit(&mut self, _timestamp: u64, length: usize) -> smoltcp::Result<Self::TxBuffer> {
        Ok(TxBuffer {
            network_file: self.network_file.clone(),
            buffer: vec![0; length],
        })
    }
}

pub struct Smolnetd {
    iface: smoltcp::iface::EthernetInterface<'static, 'static, 'static, NetworkDevice>,
    sockets: smoltcp::socket::SocketSet<'static, 'static, 'static>,
    ip_file: File,
    startup_time: Instant,
}

struct IpHandler<'a>(&'a mut Smolnetd);

impl Smolnetd {
    pub fn new(network_file: File, ip_file: File) -> Smolnetd {
        let arp_cache = smoltcp::iface::SliceArpCache::new(vec![Default::default(); 8]);
        let hardware_addr = smoltcp::wire::EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let protocol_addrs = [smoltcp::wire::IpAddress::v4(192, 168, 69, 1)];
        let network_device = NetworkDevice::new(network_file);
        Smolnetd {
            iface: smoltcp::iface::EthernetInterface::new(
                Box::new(network_device),
                Box::new(arp_cache) as Box<smoltcp::iface::ArpCache>,
                hardware_addr,
                protocol_addrs,
            ),
            sockets: smoltcp::socket::SocketSet::new(vec![]),
            startup_time: Instant::now(),
            ip_file,
        }
    }

    pub fn on_network_scheme_event(&mut self) -> Result<Option<()>> {
        let timestamp = self.get_timestamp();
        let _ = self.iface.poll(&mut self.sockets, timestamp);
        Ok(None)
    }

    pub fn on_ip_scheme_event(&mut self) -> Result<Option<()>> {
        loop {
            let mut packet = syscall::Packet::default();
            if self.ip_file.read(&mut packet)? == 0 {
                break;
            }
            IpHandler(self).handle(&mut packet);
            self.ip_file.write_all(&packet)?;
        }
        Ok(None)
    }

    fn get_timestamp(&self) -> u64 {
        let duration = Instant::now().duration_since(self.startup_time);
        let duration_ms = (duration.as_secs() * 1000) + (duration.subsec_nanos() / 1000000) as u64;
        duration_ms
    }
}

impl<'a> SchemeMut for IpHandler<'a> {
    
}
