//! Shared core for the Talk daemon: configuration, logging, socket lifecycle,
//! and message templating.

pub mod config;
pub mod logging;
pub mod sockets;
pub mod template;

pub use template::{TemplateEngine, TemplateError, TemplateSpec, TeraEngine};
