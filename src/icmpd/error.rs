use std::convert;
use std::fmt;
use std::io::Error as IOError;
use std::result;
use syscall::error::Error as SyscallError;

pub enum PacketError {
    NotEnoughData,
    IncorrectChecksum,
    NoEchoHeader,
    SubheaderAlreadPresent,
}

enum ErrorType {
    Syscall(SyscallError),
    IOError(IOError),
    PacketError(PacketError),
}

pub struct Error {
    error_type: ErrorType,
    descr: String,
}

impl Error {
    pub fn from_parsing_error<S: Into<String>>(parsing_error: PacketError, descr: S) -> Error {
        Error {
            error_type: ErrorType::PacketError(parsing_error),
            descr: descr.into(),
        }
    }
    pub fn from_syscall_error<S: Into<String>>(syscall_error: SyscallError, descr: S) -> Error {
        Error {
            error_type: ErrorType::Syscall(syscall_error),
            descr: descr.into(),
        }
    }

    pub fn from_io_error<S: Into<String>>(io_error: IOError, descr: S) -> Error {
        Error {
            error_type: ErrorType::IOError(io_error),
            descr: descr.into(),
        }
    }

    pub fn is_unrecoverable(&self) -> bool {
        match self.error_type {
            ErrorType::PacketError(_) => false,
            ErrorType::IOError(_) |
            ErrorType::Syscall(_) => true,
        }
    }
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        write!(f, "{}", match *self {
            PacketError::NotEnoughData => "not enough data",
            PacketError::IncorrectChecksum => "checksum error",
            PacketError::NoEchoHeader => "echo header is missing",
            PacketError::SubheaderAlreadPresent => "subheader is already present",
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match self.error_type {
            ErrorType::Syscall(ref syscall_error) => {
                write!(f, "{} : syscall error: {}", self.descr, syscall_error)
            }
            ErrorType::IOError(ref io_error) => {
                write!(f, "{} : io error : {}", self.descr, io_error)
            }
            ErrorType::PacketError(ref parsign_error) => {
                write!(f,
                       "{} : packet parsing error : {}",
                       self.descr,
                       parsign_error)
            }
        }
    }
}

impl convert::From<IOError> for Error {
    fn from(e: IOError) -> Self {
        Error::from_io_error(e, "")
    }
}

pub type Result<T> = result::Result<T, Error>;
pub type PacketResult<T> = result::Result<T, PacketError>;
