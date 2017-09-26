use std::ops::{Deref, DerefMut, Drop};
use std::rc::Rc;
use std::cell::RefCell;
use std::mem::swap;

type BufferStack = Rc<RefCell<Vec<Vec<u8>>>>;

pub struct Buffer {
    buffer: Vec<u8>,
    stack: BufferStack,
}

impl Buffer {
    pub fn resize(&mut self, new_len: usize) {
        self.buffer.resize(new_len, 0u8);
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

impl AsMut<[u8]> for Buffer {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        let mut tmp = vec![];
        swap(&mut tmp, &mut self.buffer);
        {
            let mut stack = self.stack.borrow_mut();
            trace!("Returning buffer: {}", stack.len());
            stack.push(tmp);
        }
    }
}

pub struct BufferPool {
    buffers_size: usize,
    stack: BufferStack,
}

impl BufferPool {
    pub fn new(buffers_size: usize) -> BufferPool {
        BufferPool {
            buffers_size,
            stack: Rc::new(RefCell::new(vec![])),
        }
    }

    pub fn get_buffer(&mut self) -> Buffer {
        let buffer = match self.stack.borrow_mut().pop() {
            None => {
                trace!("Allocating ingress buffer");
                vec![0u8; self.buffers_size]
            }
            Some(mut v) => {
                trace!("Reusing ingress buffer");
                // memsetting the buffer with `resize` would be a waste of time
                let capacity = v.capacity();
                unsafe {
                    v.set_len(capacity);
                }
                v
            }
        };

        Buffer {
            buffer,
            stack: Rc::clone(&self.stack),
        }
    }
}
