use std::convert;
use std::fmt;
use std::result;
use std::io::Error as IOError;
use syscall::error::Error as SyscallError;

#[derive(Debug)]
enum ErrorType {
    Syscall(SyscallError),
    IOError(IOError),
    Other,
}

#[derive(Debug)]
pub struct Error {
    error_type: ErrorType,
    descr: String,
}

impl Error {
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

    pub fn other_error<S: Into<String>>(descr: S) -> Error {
        Error {
            error_type: ErrorType::Other,
            descr: descr.into()
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        match self.error_type {
            ErrorType::Syscall(ref syscall_error) => {
                write!(f, "{}: syscall error: {}", self.descr, syscall_error)
            }
            ErrorType::IOError(ref io_error) => {
                write!(f, "{} : io error : {}", self.descr, io_error)
            }
            ErrorType::Other => {
                write!(f, "{}", self.descr)
            }
        }
    }
}
impl std::error::Error for Error {}

impl convert::From<IOError> for Error {
    fn from(e: IOError) -> Self {
        Error::from_io_error(e, "")
    }
}

pub type Result<T> = result::Result<T, Error>;
