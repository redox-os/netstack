use error::Result;
use std::fs::File;

pub struct Smolnetd {
    network_file: File,
    ip_file: File,
}

impl Smolnetd {
    pub fn new(network_file: File, ip_file: File) -> Smolnetd {
        Smolnetd {
            network_file,
            ip_file,
        }
    }
    pub fn on_network_scheme_event(&mut self) -> Result<Option<()>> {
        Ok(None)
    }

    pub fn on_ip_scheme_event(&mut self) -> Result<Option<()>> {
        Ok(None)
    }
}
