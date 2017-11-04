use smoltcp;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::rc::Rc;

use buffer_pool::{Buffer, BufferPool};
use arp_cache::LOOPBACK_HWADDR;

struct NetworkDeviceData {
    network_file: Rc<RefCell<File>>,
    input_queue: Rc<RefCell<VecDeque<Buffer>>>,
    local_hwaddr: smoltcp::wire::EthernetAddress,
    buffer_pool: Rc<RefCell<BufferPool>>,
}

pub struct NetworkDevice {
    data: Rc<RefCell<NetworkDeviceData>>,
}

impl NetworkDevice {
    pub const MTU: usize = 1520;

    pub fn new(
        network_file: Rc<RefCell<File>>,
        input_queue: Rc<RefCell<VecDeque<Buffer>>>,
        local_hwaddr: smoltcp::wire::EthernetAddress,
        buffer_pool: Rc<RefCell<BufferPool>>,
    ) -> NetworkDevice {
        NetworkDevice {
            data: Rc::new(RefCell::new(NetworkDeviceData {
                network_file,
                input_queue,
                local_hwaddr,
                buffer_pool,
            })),
        }
    }
}

pub struct RxToken {
    buffer: Buffer,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, _timestamp: u64, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&[u8]) -> smoltcp::Result<R>,
    {
        f(&self.buffer)
    }
}

pub struct TxToken {
    data: Rc<RefCell<NetworkDeviceData>>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, _timestamp: u64, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let data = self.data.borrow_mut();
        let mut buffer = data.buffer_pool.borrow_mut().get_buffer();
        buffer.resize(len);
        let res = f(&mut buffer)?;

        let mut loopback = false;
        if let Ok(mut frame) = smoltcp::wire::EthernetFrame::new_checked(&mut buffer) {
            if frame.dst_addr() == LOOPBACK_HWADDR {
                frame.set_dst_addr(data.local_hwaddr);
                loopback = true;
            }
        }

        if loopback {
            data.input_queue.borrow_mut().push_back(buffer.move_out());
        } else {
            data.network_file
                .borrow_mut()
                .write(&buffer)
                .map_err(|_| smoltcp::Error::Dropped)?;
        }

        Ok(res)
    }
}

impl<'a> smoltcp::phy::Device<'a> for NetworkDevice {
    type RxToken = RxToken;
    type TxToken = TxToken;

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut limits = smoltcp::phy::DeviceCapabilities::default();
        limits.max_transmission_unit = Self::MTU;
        limits.max_burst_size = Some(5);
        limits
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        let data = self.data.borrow_mut();
        let buffer = data.input_queue.borrow_mut().pop_front();

        if let Some(buffer) = buffer {
            Some((
                RxToken { buffer },
                TxToken {
                    data: Rc::clone(&self.data),
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(TxToken {
            data: Rc::clone(&self.data),
        })
    }
}
