use smoltcp;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::rc::Rc;

use buffer_pool::Buffer;

pub struct NetworkDevice {
    network_file: Rc<RefCell<File>>,
    input_queue: Rc<RefCell<VecDeque<Buffer>>>,
}

impl NetworkDevice {
    pub const MTU: usize = 1520;

    pub fn new(
        network_file: Rc<RefCell<File>>,
        input_queue: Rc<RefCell<VecDeque<Buffer>>>,
    ) -> NetworkDevice {
        NetworkDevice {
            network_file,
            input_queue,
        }
    }
}

pub struct TxBuffer {
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
    type RxBuffer = Buffer;
    type TxBuffer = TxBuffer;

    fn limits(&self) -> smoltcp::phy::DeviceLimits {
        let mut limits = smoltcp::phy::DeviceLimits::default();
        limits.max_transmission_unit = Self::MTU;
        limits.max_burst_size = Some(1);
        limits
    }

    fn receive(&mut self, _timestamp: u64) -> smoltcp::Result<Self::RxBuffer> {
        self.input_queue
            .borrow_mut()
            .pop_front()
            .ok_or(smoltcp::Error::Exhausted)
    }

    fn transmit(&mut self, _timestamp: u64, length: usize) -> smoltcp::Result<Self::TxBuffer> {
        Ok(TxBuffer {
            network_file: Rc::clone(&self.network_file),
            buffer: vec![0; length],
        })
    }
}
