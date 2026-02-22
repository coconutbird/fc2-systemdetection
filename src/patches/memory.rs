//! Memory patching utilities

use std::ffi::c_void;
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};

/// Write bytes to a memory address, handling page protection
pub fn write_bytes(address: usize, bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }

    let ptr = address as *mut u8;
    let len = bytes.len();
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);

    unsafe {
        // Make memory writable
        let protect_result = VirtualProtect(
            ptr as *const c_void,
            len,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        );

        if protect_result.is_err() {
            #[cfg(debug_assertions)]
            println!("patches: VirtualProtect failed for 0x{:08X}", address);
            return false;
        }

        // Write the bytes
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);

        // Restore original protection
        let _ = VirtualProtect(ptr as *const c_void, len, old_protect, &mut old_protect);
    }

    #[cfg(debug_assertions)]
    println!("patches: Wrote {} bytes to 0x{:08X}", len, address);

    true
}

/// Write a relative call instruction (E8 xx xx xx xx)
#[allow(dead_code)]
pub fn write_call(from: usize, to: usize) -> bool {
    let relative = (to as isize) - (from as isize) - 5;
    let mut bytes = [0u8; 5];
    bytes[0] = 0xE8; // CALL opcode
    bytes[1..5].copy_from_slice(&(relative as i32).to_le_bytes());
    write_bytes(from, &bytes)
}

/// Write a relative jump instruction (E9 xx xx xx xx)
#[allow(dead_code)]
pub fn write_jump(from: usize, to: usize) -> bool {
    let relative = (to as isize) - (from as isize) - 5;
    let mut bytes = [0u8; 5];
    bytes[0] = 0xE9; // JMP opcode
    bytes[1..5].copy_from_slice(&(relative as i32).to_le_bytes());
    write_bytes(from, &bytes)
}

/// Write NOP instructions
#[allow(dead_code)]
pub fn write_nops(address: usize, count: usize) -> bool {
    let nops = vec![0x90u8; count];
    write_bytes(address, &nops)
}
