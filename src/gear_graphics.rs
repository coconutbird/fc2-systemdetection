//! GearGraphics - Graphics detection with safe defaults
//!
//! VTable: [destructor, GetAdapterInfo, GetMonitorCount, GetDesktopResolution]
//!
//! Returns safe default values instead of calling D3D which can crash on some systems.

use std::ffi::c_void;
use windows::Win32::Foundation::RECT;
use windows::Win32::UI::WindowsAndMessaging::{
    GetDesktopWindow, GetSystemMetrics, GetWindowRect, SM_CMONITORS,
};

/// GearGraphics class - simplified structure
#[repr(C)]
pub struct GearGraphics {
    vtable: *const GearGraphicsVTable,
}

#[repr(C)]
struct GearGraphicsVTable {
    destructor: unsafe extern "thiscall" fn(*mut GearGraphics, u8) -> *mut c_void,
    get_adapter_info: unsafe extern "thiscall" fn(*mut GearGraphics, u32) -> *const c_void,
    get_monitor_count: unsafe extern "thiscall" fn(*mut GearGraphics) -> i32,
    get_desktop_resolution:
        unsafe extern "thiscall" fn(*mut GearGraphics, *mut u32, *mut u32) -> i32,
}

static GEAR_GRAPHICS_VTABLE: GearGraphicsVTable = GearGraphicsVTable {
    destructor: gear_graphics_destructor,
    get_adapter_info: gear_graphics_get_adapter_info,
    get_monitor_count: gear_graphics_get_monitor_count,
    get_desktop_resolution: gear_graphics_get_desktop_resolution,
};

unsafe extern "thiscall" fn gear_graphics_destructor(
    this: *mut GearGraphics,
    flags: u8,
) -> *mut c_void {
    if flags & 1 != 0 {
        let _ = Box::from_raw(this);
    }
    this as *mut c_void
}

/// GetAdapterInfo - returns null (game will use defaults)
unsafe extern "thiscall" fn gear_graphics_get_adapter_info(
    _this: *mut GearGraphics,
    _index: u32,
) -> *const c_void {
    std::ptr::null()
}

/// GetMonitorCount - uses GetSystemMetrics(SM_CMONITORS)
unsafe extern "thiscall" fn gear_graphics_get_monitor_count(_this: *mut GearGraphics) -> i32 {
    GetSystemMetrics(SM_CMONITORS)
}

/// GetDesktopResolution - returns desktop window dimensions
unsafe extern "thiscall" fn gear_graphics_get_desktop_resolution(
    _this: *mut GearGraphics,
    width: *mut u32,
    height: *mut u32,
) -> i32 {
    let desktop = GetDesktopWindow();
    let mut rect: RECT = std::mem::zeroed();
    let _ = GetWindowRect(desktop, &mut rect);

    if !width.is_null() {
        *width = (rect.right - rect.left) as u32;
    }
    if !height.is_null() {
        *height = (rect.bottom - rect.top) as u32;
    }

    (rect.bottom - rect.top) as i32
}

impl GearGraphics {
    pub fn new() -> Self {
        println!("systemdetection: Using safe graphics defaults (skipping D3D detection)");
        GearGraphics {
            vtable: &GEAR_GRAPHICS_VTABLE,
        }
    }
}
