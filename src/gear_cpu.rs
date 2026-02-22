//! GearCPU - CPU detection with fixed topology enumeration
//!
//! Structure layout (32 bytes + string object):
//!   0x00: vtable
//!   0x04: base class field
//!   0x08: cpu_freq_low (MHz * 1000000)
//!   0x0C: cpu_freq_high
//!   0x10: num_logical
//!   0x14: num_physical
//!   0x18: num_packages
//!   0x1C: vendor_id (4=Intel, 1=AMD)
//!   0x20: simd_level
//!   0x24: reserved
//!   0x28: cpu_info_string
//!
//! VTable: [destructor, GetCpuInfoAccess]

use cppvtable::proc::{cppvtable, cppvtable_impl};
use std::ffi::c_void;
use windows::core::PCSTR;
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE, KEY_READ,
};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetProcessAffinityMask, SetThreadAffinityMask,
};

/// GearBasicString - simplified string class at offset 0x28 of GearCPU
#[repr(C)]
pub struct GearBasicString {
    pub vtable: *const c_void, // String vtable
    pub length: u32,
    pub data: [u8; 64], // Inline buffer for short strings
}

impl Default for GearBasicString {
    fn default() -> Self {
        GearBasicString {
            vtable: std::ptr::null(),
            length: 0,
            data: [0; 64],
        }
    }
}

/// IGearCPU interface definition
#[cppvtable]
pub trait IGearCPU {
    fn destructor(&mut self, flags: u8) -> *mut c_void;
    fn get_cpu_info_access(&mut self) -> *mut GearBasicString;
}

/// GearCPU class with fixed topology detection
#[repr(C)]
pub struct GearCPU {
    pub vtable_i_gear_cpu: *const IGearCPUVTable, // offset 0x00
    _base_field: u32,                             // offset 0x04 (base class)
    cpu_freq_low: u32,                            // offset 0x08 (MHz * 1000000)
    cpu_freq_high: u32,                           // offset 0x0C
    pub num_logical: u32,                         // offset 0x10
    pub num_physical: u32,                        // offset 0x14
    pub num_packages: u32,                        // offset 0x18
    pub vendor_id: u32,                           // offset 0x1C (4=Intel, 1=AMD)
    pub simd_level: u32,                          // offset 0x20
    _reserved: u32,                               // offset 0x24
    cpu_info_string: GearBasicString,             // offset 0x28 (this + 10 DWORDs = 40 bytes)
}

#[cppvtable_impl(IGearCPU)]
impl GearCPU {
    fn destructor(&mut self, flags: u8) -> *mut c_void {
        if flags & 1 != 0 {
            unsafe {
                let _ = Box::from_raw(self as *mut Self);
            }
        }
        self as *mut Self as *mut c_void
    }

    /// GetCpuInfoAccess - returns pointer to cpu_info_string (this + 40)
    fn get_cpu_info_access(&mut self) -> *mut GearBasicString {
        &mut self.cpu_info_string as *mut GearBasicString
    }
}

impl GearCPU {
    pub fn new() -> Self {
        println!("systemdetection: Detecting CPU info");

        let (logical, physical, packages) = unsafe { Self::get_cpu_topology_fixed() };
        let cpu_mhz = unsafe { Self::get_cpu_mhz() };

        println!(
            "systemdetection: CPU: {} logical, {} physical, {} packages, {} MHz",
            logical, physical, packages, cpu_mhz
        );

        GearCPU {
            vtable_i_gear_cpu: Self::VTABLE_I_GEAR_CPU,
            _base_field: 0,
            cpu_freq_low: cpu_mhz.saturating_mul(1_000_000),
            cpu_freq_high: 0,
            num_logical: logical,
            num_physical: physical,
            num_packages: packages,
            vendor_id: 4,  // Intel
            simd_level: 8, // SSE4.2
            _reserved: 0,
            cpu_info_string: GearBasicString::default(),
        }
    }

    /// Fixed CPU topology detection
    /// Key fix: `while (mask != 0 && mask <= system_affinity)` instead of `while (1 << i)`
    unsafe fn get_cpu_topology_fixed() -> (u32, u32, u32) {
        let mut process_affinity: usize = 0;
        let mut system_affinity: usize = 0;

        let process = GetCurrentProcess();
        let _ = GetProcessAffinityMask(process, &mut process_affinity, &mut system_affinity);

        let mut logical_count = 0u32;
        let mut mask: usize = 1;
        let thread = GetCurrentThread();

        // Fixed: proper bounds checking
        while mask != 0 && mask <= system_affinity {
            if SetThreadAffinityMask(thread, mask) != 0 {
                logical_count += 1;
            }
            mask = mask.wrapping_shl(1);
        }

        let _ = SetThreadAffinityMask(thread, process_affinity);

        if logical_count == 0 {
            let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
            GetSystemInfo(&mut sys_info);
            logical_count = sys_info.dwNumberOfProcessors;
        }

        let physical_count = logical_count.div_ceil(2).max(1);
        (logical_count.max(1), physical_count, 1)
    }

    unsafe fn get_cpu_mhz() -> u32 {
        let key_path = b"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\0";
        let value_name = b"~MHz\0";
        let mut hkey = std::mem::zeroed();

        if RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            PCSTR::from_raw(key_path.as_ptr()),
            Some(0),
            KEY_READ,
            &mut hkey,
        )
        .is_ok()
        {
            let mut mhz: u32 = 0;
            let mut size = 4u32;
            let _ = RegQueryValueExA(
                hkey,
                PCSTR::from_raw(value_name.as_ptr()),
                None,
                None,
                Some(&mut mhz as *mut u32 as *mut u8),
                Some(&mut size),
            );
            let _ = RegCloseKey(hkey);
            if mhz > 0 {
                return mhz;
            }
        }
        3000
    }
}
