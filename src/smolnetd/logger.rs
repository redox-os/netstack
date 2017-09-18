use log::{set_logger_raw, Log, LogLevelFilter, LogMetadata, LogRecord};

struct Logger;

impl Log for Logger {
    fn enabled(&self, _: &LogMetadata) -> bool {
        true
    }

    fn log(&self, record: &LogRecord) {
        println!("{}: {}", record.level(), record.args());
    }
}

pub fn init_logger() {
    unsafe {
        set_logger_raw(|max_log_level| {
            max_log_level.set(LogLevelFilter::Trace);
            &Logger
        }).expect("Can't initialize logger");
    }
}
