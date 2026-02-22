//! Dunia.dll runtime patches
//!
//! This module applies fixes to Dunia.dll at runtime, similar to Far Cry 2 Multi Fixer.
//! Since systemdetection.dll is loaded by Dunia.dll before initialization completes,
//! we can safely patch Dunia.dll from here.
//!
//! All signature scans are performed upfront before any patches are applied,
//! ensuring that patches don't corrupt signatures we haven't scanned yet.

mod hooks;
mod memory;
mod sigscan;

use memory::write_bytes;
use sigscan::{Pattern, scan_module};
use windows::Win32::System::LibraryLoader::GetModuleHandleA;
use windows::core::PCSTR;

/// Signature definitions
mod signatures {
    // Jackal Tapes: cmp byte ptr [esi+74h], 0 | jnz short | cmp ecx, edx | jnz
    pub const JACKAL_TAPES: &str = "80 7E 74 00 75 ?? 3B CA 75";

    // DevMode: cmp byte ptr [ecx+offset], 0 | mov edx, [esp+arg] | jnz
    pub const DEVMODE: &str = "80 79 ?? 00 8B 54 24 ?? 75";

    // Predecessor Tapes: mov ecx, [ecx+0Ch] | test ecx, ecx | jz
    // Function checks online service pointer, patch makes it always skip the null check
    pub const PREDECESSOR_TAPES: &str = "8B 49 0C 85 C9 74 ?? 8B 44 24";

    // Machetes: sub esp, ?? | push ebx | lea eax, [esp+??] | push eax | push
    // This is the prologue of IsMachetesUnlocked function
    pub const MACHETES: &str = "83 EC ?? 53 8D 44 24 ?? 50 68";

    // No Blinking Items: String literals to corrupt
    pub const MESH_HIGHLIGHT: &str = "4D 65 73 68 5F 48 69 67 68 6C 69 67 68 74"; // "Mesh_Highlight"
    pub const ARCH_BLINK: &str = "61 72 63 68 42 6C 69 6E 6B"; // "archBlink"
    pub const SAVE_DISK: &str = "67 61 64 67 65 74 73 2E 4F 62 6A 65 63 74 69 76 65 49 63 6F 6E 73 2E 53 61 76 65 44 69 73 6B"; // "gadgets.ObjectiveIcons.SaveDisk"
}

/// Cached addresses from signature scans (found before patching)
struct PatchAddresses {
    jackal_tapes: Option<usize>,
    devmode: Option<usize>,
    predecessor_tapes: Option<usize>,
    machetes: Option<usize>,
    mesh_highlight: Option<usize>,
    arch_blink: Option<usize>,
    save_disk: Option<usize>,
}

impl PatchAddresses {
    /// Scan for all signatures upfront, before any patches are applied
    fn scan(base: usize) -> Self {
        #[cfg(debug_assertions)]
        println!("patches: Scanning for all signatures...");

        let jackal_tapes =
            Pattern::parse(signatures::JACKAL_TAPES).and_then(|p| scan_module(base, &p));
        let devmode = Pattern::parse(signatures::DEVMODE).and_then(|p| scan_module(base, &p));
        let predecessor_tapes =
            Pattern::parse(signatures::PREDECESSOR_TAPES).and_then(|p| scan_module(base, &p));
        let machetes = Pattern::parse(signatures::MACHETES).and_then(|p| scan_module(base, &p));
        let mesh_highlight =
            Pattern::parse(signatures::MESH_HIGHLIGHT).and_then(|p| scan_module(base, &p));
        let arch_blink = Pattern::parse(signatures::ARCH_BLINK).and_then(|p| scan_module(base, &p));
        let save_disk = Pattern::parse(signatures::SAVE_DISK).and_then(|p| scan_module(base, &p));

        #[cfg(debug_assertions)]
        {
            println!(
                "patches:   Jackal Tapes:      {:?}",
                jackal_tapes.map(|a| format!("0x{:08X}", a))
            );
            println!(
                "patches:   DevMode:           {:?}",
                devmode.map(|a| format!("0x{:08X}", a))
            );
            println!(
                "patches:   Predecessor Tapes: {:?}",
                predecessor_tapes.map(|a| format!("0x{:08X}", a))
            );
            println!(
                "patches:   Machetes:          {:?}",
                machetes.map(|a| format!("0x{:08X}", a))
            );
            println!(
                "patches:   Mesh_Highlight:    {:?}",
                mesh_highlight.map(|a| format!("0x{:08X}", a))
            );
            println!(
                "patches:   archBlink:         {:?}",
                arch_blink.map(|a| format!("0x{:08X}", a))
            );
            println!(
                "patches:   SaveDisk:          {:?}",
                save_disk.map(|a| format!("0x{:08X}", a))
            );
        }

        Self {
            jackal_tapes,
            devmode,
            predecessor_tapes,
            machetes,
            mesh_highlight,
            arch_blink,
            save_disk,
        }
    }
}

/// Apply all enabled patches to Dunia.dll
pub fn apply_patches() {
    // Get Dunia.dll base address
    let dunia_base =
        unsafe { GetModuleHandleA(PCSTR::from_raw(c"Dunia.dll".as_ptr() as *const u8)) };

    let Ok(dunia) = dunia_base else {
        #[cfg(debug_assertions)]
        println!("patches: Dunia.dll not loaded, skipping patches");
        return;
    };

    if dunia.is_invalid() {
        #[cfg(debug_assertions)]
        println!("patches: Dunia.dll handle invalid, skipping patches");
        return;
    }

    let base = dunia.0 as usize;

    #[cfg(debug_assertions)]
    println!("patches: Dunia.dll base = 0x{:08X}", base);

    // IMPORTANT: Scan for ALL signatures BEFORE applying any patches
    // This prevents patches from corrupting signatures we haven't found yet
    let addrs = PatchAddresses::scan(base);
    let hook_addrs = hooks::HookAddresses::scan(base);

    // Now apply patches using the cached addresses
    apply_jackal_tapes_fix(&addrs);
    apply_no_blinking_items(&addrs);
    apply_devmode_unlock(&addrs);
    apply_predecessor_tapes_unlock(&addrs);
    apply_machetes_unlock(&addrs);

    // Install function hooks (for FOV slider, etc.)
    if let Err(_e) = hooks::install_hooks(&hook_addrs) {
        #[cfg(debug_assertions)]
        println!("patches: Failed to install hooks: {:?}", _e);
    }
}

/// Fix: Jackal Tapes - All tapes in Southern map play correct recordings
///
/// The bug: In the Southern map, some Jackal tape pickups play incorrect recordings.
/// This is caused by an incorrect jump offset in the tape lookup logic.
fn apply_jackal_tapes_fix(addrs: &PatchAddresses) {
    let Some(addr) = addrs.jackal_tapes else {
        #[cfg(debug_assertions)]
        println!("patches: Jackal Tapes signature not found, skipping");
        return;
    };

    // The jump offset byte is at offset 5 in the pattern (after "75")
    let patch_addr = addr + 5;

    #[cfg(debug_assertions)]
    println!("patches: Applying Jackal Tapes fix at 0x{:08X}", patch_addr);

    // Change jump offset (add 0x10 to fix tape index calculation)
    let current = unsafe { *(patch_addr as *const u8) };
    write_bytes(patch_addr, &[current.wrapping_add(0x10)]);
}

/// Visual: No Blinking Items - Remove highlight blinking on interactables
///
/// Patches string literals to break the shader lookup, disabling the blinking effect.
fn apply_no_blinking_items(addrs: &PatchAddresses) {
    // Patch "Mesh_Highlight" - change '_' to '.'
    if let Some(addr) = addrs.mesh_highlight {
        #[cfg(debug_assertions)]
        println!("patches: Patching Mesh_Highlight at 0x{:08X}", addr);
        write_bytes(addr + 4, &[0x2E]); // offset 4 = '_'
    }

    // Patch "archBlink" - change 'k' to '.'
    if let Some(addr) = addrs.arch_blink {
        #[cfg(debug_assertions)]
        println!("patches: Patching archBlink at 0x{:08X}", addr);
        write_bytes(addr + 8, &[0x2E]); // offset 8 = 'k'
    }

    // Patch "gadgets.ObjectiveIcons.SaveDisk" - change 'k' to '.'
    if let Some(addr) = addrs.save_disk {
        #[cfg(debug_assertions)]
        println!("patches: Patching SaveDisk at 0x{:08X}", addr);
        write_bytes(addr + 30, &[0x2E]); // offset 30 = 'k'
    }
}

/// Fix: DevMode Unlock - Enable developer console commands
///
/// Patches CConsoleService_IsCommandVisible to always skip the devmode check,
/// making all "ConsoleDeveloperOnly" commands visible and usable.
fn apply_devmode_unlock(addrs: &PatchAddresses) {
    let Some(addr) = addrs.devmode else {
        #[cfg(debug_assertions)]
        println!("patches: DevMode signature not found, skipping");
        return;
    };

    // The jnz opcode is at offset 8 in the pattern
    let jnz_addr = addr + 8;

    #[cfg(debug_assertions)]
    println!("patches: Applying DevMode unlock at 0x{:08X}", jnz_addr);

    // Change jnz (0x75) to jmp (0xEB) - always skip the devmode check
    write_bytes(jnz_addr, &[0xEB]);
}

/// Unlock: Predecessor Tapes - Unlock 7 bonus missions
///
/// The predecessor tapes were originally tied to an online Ubisoft account.
/// This patches IsPredecessorTapesUnlocked to always return true.
fn apply_predecessor_tapes_unlock(addrs: &PatchAddresses) {
    let Some(addr) = addrs.predecessor_tapes else {
        #[cfg(debug_assertions)]
        println!("patches: Predecessor Tapes signature not found, skipping");
        return;
    };

    // Pattern: 8B 49 0C 85 C9 74 ?? 8B 44 24
    // The jz opcode is at offset 5, jump offset at offset 6
    // We change "74 ??" (jz) to "EB 0E" (jmp +14) to skip the null check
    let jz_addr = addr + 5;

    #[cfg(debug_assertions)]
    println!(
        "patches: Applying Predecessor Tapes unlock at 0x{:08X}",
        jz_addr
    );

    // Change jz (0x74) to jmp (0xEB), and set offset to 0x0E
    write_bytes(jz_addr, &[0xEB, 0x0E]);
}

/// Unlock: Machetes - Unlock 2 bonus machete skins
///
/// The bonus machetes were originally unlocked via a registry key.
/// This patches IsMachetesUnlocked to always return true.
fn apply_machetes_unlock(addrs: &PatchAddresses) {
    let Some(addr) = addrs.machetes else {
        #[cfg(debug_assertions)]
        println!("patches: Machetes signature not found, skipping");
        return;
    };

    // Signature is at function prologue (sub esp | push ebx | lea eax | push eax | push)
    // Offset from function start to "mov al, bl" (8A C3) is 0x69 (105 bytes)
    // We change "mov al, bl" to "mov al, 1" (B0 01) to always return true
    let patch_addr = addr + 0x69;

    #[cfg(debug_assertions)]
    println!("patches: Applying Machetes unlock at 0x{:08X}", patch_addr);

    // Change "mov al, bl" (8A C3) to "mov al, 1" (B0 01)
    write_bytes(patch_addr, &[0xB0, 0x01]);
}
