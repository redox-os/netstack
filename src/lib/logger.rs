use redox_log::{OutputBuilder, RedoxLogger};

pub fn init_logger(process_name: &str) {
    if let Err(_) = RedoxLogger::new()
            .with_output(
                OutputBuilder::stdout()
                    .with_ansi_escape_codes()
                    .flush_on_newline(true)
                    .with_filter(log::LevelFilter::Trace)
                    .build(),
            )
            .with_process_name(process_name.into())
            .enable() {
        eprintln!("{process_name}: Failed to init logger")
    }
}
