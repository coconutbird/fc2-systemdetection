//! GearHardware - Main hardware detection class
//!
//! Structure layout (32 bytes):
//!   0x00: vtable
//!   0x04: m_cpu (GearCPU*)
//!   0x08: m_logical_disks (GearLogicalDisks*)
//!   0x0C: m_memory (GearMemory*)
//!   0x10: m_network (GearNetwork*)
//!   0x14: m_os (GearOS*)
//!   0x18: m_graphics (GearGraphics*)
//!   0x1C: m_audio (GearAudio*)
//!
//! VTable: [destructor, GetCpu, GetLogicalDisks, GetMemory, GetNetwork, GetOS, GetGraphics, GetAudio]

use super::gear_cpu::GearCPU;
use super::gear_graphics::GearGraphics;
use cppvtable::proc::{cppvtable, cppvtable_impl};
use std::ffi::c_void;
use std::ptr::null_mut;

/// Stub classes for subsystems we don't need to fully implement
#[repr(C)]
pub struct GearLogicalDisks {
    _vtable: *const c_void,
}
#[repr(C)]
pub struct GearMemory {
    _vtable: *const c_void,
}
#[repr(C)]
pub struct GearNetwork {
    _vtable: *const c_void,
}
#[repr(C)]
pub struct GearOS {
    _vtable: *const c_void,
}
#[repr(C)]
pub struct GearAudio {
    _vtable: *const c_void,
}

/// IGearHardware interface definition
#[cppvtable]
pub trait IGearHardware {
    fn destructor(&mut self, flags: u8) -> *mut c_void;
    fn get_cpu(&mut self) -> *mut GearCPU;
    fn get_logical_disks(&mut self) -> *mut GearLogicalDisks;
    fn get_memory(&mut self) -> *mut GearMemory;
    fn get_network(&mut self) -> *mut GearNetwork;
    fn get_os(&mut self) -> *mut GearOS;
    fn get_graphics(&mut self) -> *mut GearGraphics;
    fn get_audio(&mut self) -> *mut GearAudio;
}

/// GearHardware class (32 bytes)
#[repr(C)]
pub struct GearHardware {
    pub vtable_i_gear_hardware: *const IGearHardwareVTable, // offset 0x00
    m_cpu: *mut GearCPU,                                    // offset 0x04
    m_logical_disks: *mut GearLogicalDisks,                 // offset 0x08
    m_memory: *mut GearMemory,                              // offset 0x0C
    m_network: *mut GearNetwork,                            // offset 0x10
    m_os: *mut GearOS,                                      // offset 0x14
    m_graphics: *mut GearGraphics,                          // offset 0x18
    m_audio: *mut GearAudio,                                // offset 0x1C
}

unsafe impl Send for GearHardware {}
unsafe impl Sync for GearHardware {}

#[cppvtable_impl(IGearHardware)]
impl GearHardware {
    fn destructor(&mut self, flags: u8) -> *mut c_void {
        unsafe {
            if !self.m_cpu.is_null() {
                let _ = Box::from_raw(self.m_cpu);
            }
            if !self.m_graphics.is_null() {
                let _ = Box::from_raw(self.m_graphics);
            }
            if flags & 1 != 0 {
                let _ = Box::from_raw(self as *mut Self);
            }
        }
        self as *mut Self as *mut c_void
    }

    fn get_cpu(&mut self) -> *mut GearCPU {
        if self.m_cpu.is_null() {
            self.m_cpu = Box::into_raw(Box::new(GearCPU::new()));
        }
        self.m_cpu
    }

    fn get_logical_disks(&mut self) -> *mut GearLogicalDisks {
        self.m_logical_disks
    }

    fn get_memory(&mut self) -> *mut GearMemory {
        self.m_memory
    }

    fn get_network(&mut self) -> *mut GearNetwork {
        self.m_network
    }

    fn get_os(&mut self) -> *mut GearOS {
        self.m_os
    }

    fn get_graphics(&mut self) -> *mut GearGraphics {
        if self.m_graphics.is_null() {
            self.m_graphics = Box::into_raw(Box::new(GearGraphics::new()));
        }
        self.m_graphics
    }

    fn get_audio(&mut self) -> *mut GearAudio {
        self.m_audio
    }
}

impl Default for GearHardware {
    fn default() -> Self {
        Self::new()
    }
}

impl GearHardware {
    pub fn new() -> Self {
        println!("systemdetection: Initializing GearHardware");
        GearHardware {
            vtable_i_gear_hardware: Self::VTABLE_I_GEAR_HARDWARE,
            m_cpu: null_mut(),
            m_logical_disks: null_mut(),
            m_memory: null_mut(),
            m_network: null_mut(),
            m_os: null_mut(),
            m_graphics: null_mut(),
            m_audio: null_mut(),
        }
    }
}
