//! Core contracts for MirrorSwitch.
//!
//! Front ends and tool adapters share these types. The remote catalog is data
//! only: it can select among adapter capabilities compiled into the binary, but
//! it cannot provide commands or executable extensions.

pub mod adapter;
pub mod catalog;
pub mod context;
pub mod plan;
pub mod platform;
pub mod transaction;

pub use adapter::{Adapter, AdapterError, Runtime};
pub use catalog::MirrorCatalog;
pub use context::SystemContext;
pub use transaction::{ApplyOutcome, TransactionEngine, TransactionError};
