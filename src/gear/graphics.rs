//! GearGraphics - Graphics detection with safe defaults
//!
//! VTable: [destructor, GetAdapterInfo, GetMonitorCount, GetDesktopResolution]
//!
//! Returns safe default values instead of calling D3D which can crash on some systems.

use cppvtable::proc::cppvtable;
use cppvtable::proc::cppvtable_impl;
use std::ffi::c_void;
use windows::Win32::Foundation::RECT;
use windows::Win32::UI::WindowsAndMessaging::{
    GetDesktopWindow, GetSystemMetrics, GetWindowRect, SM_CMONITORS,
};

/// IGearGraphics interface definition
#[cppvtable]
pub trait IGearGraphics {
    fn destructor(&mut self, flags: u8) -> *mut c_void;
    fn get_adapter_info(&mut self, index: u32) -> *const c_void;
    fn get_monitor_count(&mut self) -> i32;
    fn get_desktop_resolution(&mut self, width: *mut u32, height: *mut u32) -> i32;
}

/// GearGraphics class - simplified structure
#[repr(C)]
pub struct GearGraphics {
    pub vtable_i_gear_graphics: *const IGearGraphicsVTable,
}

#[cppvtable_impl(IGearGraphics)]
impl GearGraphics {
    fn destructor(&mut self, flags: u8) -> *mut c_void {
        if flags & 1 != 0 {
            unsafe {
                let _ = Box::from_raw(self as *mut Self);
            }
        }
        self as *mut Self as *mut c_void
    }

    /// GetAdapterInfo - returns null (game will use defaults)
    fn get_adapter_info(&mut self, _index: u32) -> *const c_void {
        std::ptr::null()
    }

    /// GetMonitorCount - uses GetSystemMetrics(SM_CMONITORS)
    fn get_monitor_count(&mut self) -> i32 {
        unsafe { GetSystemMetrics(SM_CMONITORS) }
    }

    /// GetDesktopResolution - returns desktop window dimensions
    fn get_desktop_resolution(&mut self, width: *mut u32, height: *mut u32) -> i32 {
        unsafe {
            let desktop = GetDesktopWindow();
            let mut rect: RECT = std::mem::zeroed();
            let _ = GetWindowRect(desktop, &mut rect);

            if !width.is_null() {
                *width = (rect.right - rect.left) as u32;
            }
            if !height.is_null() {
                *height = (rect.bottom - rect.top) as u32;
            }

            rect.bottom - rect.top
        }
    }
}

impl GearGraphics {
    pub fn new() -> Self {
        #[cfg(debug_assertions)]
        println!("systemdetection: Initializing GearGraphics");
        GearGraphics {
            vtable_i_gear_graphics: Self::VTABLE_I_GEAR_GRAPHICS,
        }
    }
}
