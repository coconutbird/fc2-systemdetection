//! Far Cry 2 systemdetection.dll drop-in replacement

mod gear_cpu;
mod gear_graphics;
mod gear_hardware;
mod gear_score;

pub use gear_hardware::GearHardware;
pub use gear_score::GearScore;

use std::ffi::c_void;
use std::sync::OnceLock;
use windows::Win32::Foundation::{BOOL, HMODULE, TRUE};
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

/// DLL entry point
///
/// # Safety
/// Called by Windows when the DLL is loaded/unloaded.
#[no_mangle]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    _hinst_dll: HMODULE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> BOOL {
    if fdw_reason == DLL_PROCESS_ATTACH {
        #[cfg(debug_assertions)]
        {
            init_console();
            println!("===========================================");
            println!("  Far Cry 2 - systemdetection.dll replacement");
            println!("===========================================");
        }
    }
    TRUE
}

/// Initialize console for debug output
#[cfg(debug_assertions)]
unsafe fn init_console() {
    use windows::core::PCSTR;
    use windows::Win32::System::Console::{AllocConsole, SetConsoleTitleA};

    let _ = AllocConsole();
    let _ = SetConsoleTitleA(PCSTR::from_raw(c"FC2 SystemDetection".as_ptr() as *const u8));

    extern "C" {
        fn freopen(filename: *const i8, mode: *const i8, stream: *mut c_void) -> *mut c_void;
        fn __acrt_iob_func(index: u32) -> *mut c_void;
    }

    freopen(c"CONOUT$".as_ptr(), c"w".as_ptr(), __acrt_iob_func(1)); // stdout
    freopen(c"CONOUT$".as_ptr(), c"w".as_ptr(), __acrt_iob_func(2)); // stderr
}

/// Global singleton for GearHardware
static GEAR_HARDWARE: OnceLock<Box<GearHardware>> = OnceLock::new();

/// Global singleton for GearScore  
static GEAR_SCORE: OnceLock<Box<GearScore>> = OnceLock::new();

/// Get the GearHardware singleton instance
///
/// # Safety
/// This function is called from C code and returns a raw pointer
#[no_mangle]
pub unsafe extern "C" fn GetHardwareInstance() -> *mut GearHardware {
    let hardware = GEAR_HARDWARE.get_or_init(|| {
        println!("systemdetection: Creating GearHardware instance");
        Box::new(GearHardware::new())
    });

    hardware.as_ref() as *const GearHardware as *mut GearHardware
}

/// Get the GearScore singleton instance
///
/// # Safety
/// This function is called from C code and returns a raw pointer
#[no_mangle]
pub unsafe extern "C" fn GetScoreInstance() -> *mut GearScore {
    let score = GEAR_SCORE.get_or_init(|| {
        println!("systemdetection: Creating GearScore instance");
        Box::new(GearScore::new())
    });

    score.as_ref() as *const GearScore as *mut GearScore
}
