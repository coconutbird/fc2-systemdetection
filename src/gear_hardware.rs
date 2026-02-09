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

/// GearHardware class (32 bytes)
#[repr(C)]
pub struct GearHardware {
    vtable: *const GearHardwareVTable,      // offset 0x00
    m_cpu: *mut GearCPU,                    // offset 0x04
    m_logical_disks: *mut GearLogicalDisks, // offset 0x08
    m_memory: *mut GearMemory,              // offset 0x0C
    m_network: *mut GearNetwork,            // offset 0x10
    m_os: *mut GearOS,                      // offset 0x14
    m_graphics: *mut GearGraphics,          // offset 0x18
    m_audio: *mut GearAudio,                // offset 0x1C
}

unsafe impl Send for GearHardware {}
unsafe impl Sync for GearHardware {}

#[repr(C)]
struct GearHardwareVTable {
    destructor: unsafe extern "thiscall" fn(*mut GearHardware, u8) -> *mut c_void,
    get_cpu: unsafe extern "thiscall" fn(*mut GearHardware) -> *mut GearCPU,
    get_logical_disks: unsafe extern "thiscall" fn(*mut GearHardware) -> *mut GearLogicalDisks,
    get_memory: unsafe extern "thiscall" fn(*mut GearHardware) -> *mut GearMemory,
    get_network: unsafe extern "thiscall" fn(*mut GearHardware) -> *mut GearNetwork,
    get_os: unsafe extern "thiscall" fn(*mut GearHardware) -> *mut GearOS,
    get_graphics: unsafe extern "thiscall" fn(*mut GearHardware) -> *mut GearGraphics,
    get_audio: unsafe extern "thiscall" fn(*mut GearHardware) -> *mut GearAudio,
}

static GEAR_HARDWARE_VTABLE: GearHardwareVTable = GearHardwareVTable {
    destructor: gear_hardware_destructor,
    get_cpu: gear_hardware_get_cpu,
    get_logical_disks: gear_hardware_get_logical_disks,
    get_memory: gear_hardware_get_memory,
    get_network: gear_hardware_get_network,
    get_os: gear_hardware_get_os,
    get_graphics: gear_hardware_get_graphics,
    get_audio: gear_hardware_get_audio,
};

unsafe extern "thiscall" fn gear_hardware_destructor(
    this: *mut GearHardware,
    flags: u8,
) -> *mut c_void {
    if !(*this).m_cpu.is_null() {
        let _ = Box::from_raw((*this).m_cpu);
    }
    if !(*this).m_graphics.is_null() {
        let _ = Box::from_raw((*this).m_graphics);
    }
    if flags & 1 != 0 {
        let _ = Box::from_raw(this);
    }
    this as *mut c_void
}

unsafe extern "thiscall" fn gear_hardware_get_cpu(this: *mut GearHardware) -> *mut GearCPU {
    if (*this).m_cpu.is_null() {
        (*this).m_cpu = Box::into_raw(Box::new(GearCPU::new()));
    }
    (*this).m_cpu
}

unsafe extern "thiscall" fn gear_hardware_get_logical_disks(
    this: *mut GearHardware,
) -> *mut GearLogicalDisks {
    (*this).m_logical_disks
}

unsafe extern "thiscall" fn gear_hardware_get_memory(this: *mut GearHardware) -> *mut GearMemory {
    (*this).m_memory
}

unsafe extern "thiscall" fn gear_hardware_get_network(this: *mut GearHardware) -> *mut GearNetwork {
    (*this).m_network
}

unsafe extern "thiscall" fn gear_hardware_get_os(this: *mut GearHardware) -> *mut GearOS {
    (*this).m_os
}

unsafe extern "thiscall" fn gear_hardware_get_graphics(
    this: *mut GearHardware,
) -> *mut GearGraphics {
    if (*this).m_graphics.is_null() {
        (*this).m_graphics = Box::into_raw(Box::new(GearGraphics::new()));
    }
    (*this).m_graphics
}

unsafe extern "thiscall" fn gear_hardware_get_audio(this: *mut GearHardware) -> *mut GearAudio {
    (*this).m_audio
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
            vtable: &GEAR_HARDWARE_VTABLE,
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
