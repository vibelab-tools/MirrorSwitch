//! Core contracts for MirrorSwitch.
//!
//! Front ends and tool adapters share these types. The remote catalog is data
//! only: it can select among adapter capabilities compiled into the binary, but
//! it cannot provide commands or executable extensions.

pub mod adapter;
pub mod adapters;
pub mod catalog;
pub mod catalog_update;
pub mod context;
pub mod detection;
pub mod frontend;
pub mod plan;
pub mod platform;
pub mod selection;
pub mod transaction;
pub mod tui;

pub use adapter::{Adapter, AdapterError, Runtime};
pub use catalog::MirrorCatalog;
pub use context::SystemContext;
pub use transaction::{ApplyOutcome, TransactionEngine, TransactionError};
