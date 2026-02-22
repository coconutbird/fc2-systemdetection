//! Gear hardware detection subsystem
//!
//! This module contains the hardware detection classes that Far Cry 2 uses
//! to determine system capabilities.

mod cpu;
mod graphics;
mod hardware;
mod score;

pub use hardware::GearHardware;
pub use score::GearScore;
