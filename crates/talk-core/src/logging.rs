use tracing_subscriber::EnvFilter;

/// Initialise the global tracing subscriber from a log-level string
/// (e.g. "info", "talk_core=debug,talkd=trace").
pub fn init(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .try_init();
}
