use smoltcp;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::rc::Rc;

use smoltcp::time::Instant;
use smoltcp::wire::EthernetAddress;
use crate::buffer_pool::{Buffer, BufferPool};

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
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub struct TxToken {
    data: Rc<RefCell<NetworkDeviceData>>,
}

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let data = self.data.borrow_mut();
        let mut buffer = data.buffer_pool.borrow_mut().get_buffer();
        buffer.resize(len);
        let res = f(&mut buffer);

        let mut loopback = false;
        if let Ok(mut frame) = smoltcp::wire::EthernetFrame::new_checked(&mut buffer) {
            if frame.dst_addr() == EthernetAddress::default() {
                frame.set_dst_addr(data.local_hwaddr);
                loopback = true;
            }
        }

        if loopback {
            data.input_queue.borrow_mut().push_back(buffer.move_out());
        } else {
            // TODO: Handle error
            data.network_file
                .borrow_mut()
                .write(&buffer);
        }

        res
    }
}

impl smoltcp::phy::Device for NetworkDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken;

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut limits = smoltcp::phy::DeviceCapabilities::default();
        limits.max_transmission_unit = Self::MTU;
        limits.max_burst_size = Some(20);
        limits
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
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

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            data: Rc::clone(&self.data),
        })
    }
}
