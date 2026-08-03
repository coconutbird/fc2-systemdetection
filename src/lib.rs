//! Far Cry 2 systemdetection.dll drop-in replacement

mod gear;
mod patches;

pub use gear::GearHardware;
pub use gear::GearScore;
pub use patches::{DuniaFileValidation, OfflinePatchState, ValidatedPatch, validate_dunia_file};

use std::ffi::c_void;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::SystemServices::DLL_PROCESS_ATTACH;

static SELF_MODULE: AtomicUsize = AtomicUsize::new(0);
static RUNTIME_INITIALIZED: OnceLock<()> = OnceLock::new();

/// DLL entry point
///
/// # Safety
/// Called by Windows when the DLL is loaded/unloaded.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "system" fn DllMain(
    hinst_dll: HMODULE,
    fdw_reason: u32,
    _lpv_reserved: *mut c_void,
) -> i32 {
    if fdw_reason == DLL_PROCESS_ATTACH {
        SELF_MODULE.store(hinst_dll as usize, Ordering::Release);
    }
    1 // TRUE
}

/// Perform allocation, file access, PE parsing, and memory patching outside
/// `DllMain` and the Windows loader lock.
fn ensure_runtime_initialized() {
    RUNTIME_INITIALIZED.get_or_init(|| {
        #[cfg(debug_assertions)]
        unsafe {
            init_console();
            println!("===========================================");
            println!("  Far Cry 2 - systemdetection.dll replacement");
            println!("===========================================");
        }

        let module = SELF_MODULE.load(Ordering::Acquire);
        patches::initialize(module as HMODULE);
    });
}

/// Initialize console for debug output
#[cfg(debug_assertions)]
unsafe fn init_console() {
    use windows_sys::Win32::System::Console::{AllocConsole, SetConsoleTitleA};

    unsafe {
        let _ = AllocConsole();
        let _ = SetConsoleTitleA(c"FC2 SystemDetection".as_ptr() as *const u8);

        unsafe extern "C" {
            fn freopen(filename: *const i8, mode: *const i8, stream: *mut c_void) -> *mut c_void;
            fn __acrt_iob_func(index: u32) -> *mut c_void;
        }

        freopen(c"CONOUT$".as_ptr(), c"w".as_ptr(), __acrt_iob_func(1)); // stdout
        freopen(c"CONOUT$".as_ptr(), c"w".as_ptr(), __acrt_iob_func(2)); // stderr
    }
}

/// Global singleton for GearHardware
static GEAR_HARDWARE: OnceLock<Box<GearHardware>> = OnceLock::new();

/// Global singleton for GearScore
static GEAR_SCORE: OnceLock<Box<GearScore>> = OnceLock::new();

/// Get the GearHardware singleton instance
///
/// # Safety
/// This function is called from C code and returns a raw pointer
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GetHardwareInstance() -> *mut GearHardware {
    ensure_runtime_initialized();

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn GetScoreInstance() -> *mut GearScore {
    ensure_runtime_initialized();

    let score = GEAR_SCORE.get_or_init(|| {
        println!("systemdetection: Creating GearScore instance");
        Box::new(GearScore::new())
    });

    score.as_ref() as *const GearScore as *mut GearScore
}
