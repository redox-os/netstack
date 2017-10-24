use smoltcp;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::rc::Rc;

use buffer_pool::{Buffer, BufferPool};
use arp_cache::LOOPBACK_HWADDR;

pub struct NetworkDevice {
    network_file: Rc<RefCell<File>>,
    input_queue: Rc<RefCell<VecDeque<Buffer>>>,
    local_hwaddr: smoltcp::wire::EthernetAddress,
    buffer_pool: Rc<RefCell<BufferPool>>,
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
            network_file,
            input_queue,
            local_hwaddr,
            buffer_pool,
        }
    }
}

pub struct TxBuffer {
    buffer: Buffer,
    network_file: Rc<RefCell<File>>,
    input_queue: Rc<RefCell<VecDeque<Buffer>>>,
    local_hwaddr: smoltcp::wire::EthernetAddress,
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
        let mut loopback = false;

        if let Ok(mut frame) = smoltcp::wire::EthernetFrame::new_checked(&mut self.buffer) {
            if frame.dst_addr() == LOOPBACK_HWADDR {
                frame.set_dst_addr(self.local_hwaddr);
                loopback = true;
            }
        }

        if loopback {
            self.input_queue
                .borrow_mut()
                .push_back(self.buffer.move_out());
        } else {
            let _ = self.network_file.borrow_mut().write(&self.buffer);
        }
    }
}

impl smoltcp::phy::Device for NetworkDevice {
    type RxBuffer = Buffer;
    type TxBuffer = TxBuffer;

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut limits = smoltcp::phy::DeviceCapabilities::default();
        limits.max_transmission_unit = Self::MTU;
        limits.max_burst_size = Some(5);
        limits
    }

    fn receive(&mut self, _timestamp: u64) -> smoltcp::Result<Self::RxBuffer> {
        self.input_queue
            .borrow_mut()
            .pop_front()
            .ok_or(smoltcp::Error::Exhausted)
    }

    fn transmit(&mut self, _timestamp: u64, length: usize) -> smoltcp::Result<Self::TxBuffer> {
        let mut buffer = self.buffer_pool.borrow_mut().get_buffer();
        buffer.resize(length);
        Ok(TxBuffer {
            network_file: Rc::clone(&self.network_file),
            buffer,
            input_queue: Rc::clone(&self.input_queue),
            local_hwaddr: self.local_hwaddr,
        })
    }
}
