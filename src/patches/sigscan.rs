//! Signature scanning for pattern matching in memory
//!
//! Supports wildcard bytes using `??` in patterns.

use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY,
    PAGE_READWRITE, VirtualQuery,
};
use windows::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

/// A parsed signature pattern with optional wildcard bytes
pub struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<bool>, // true = must match, false = wildcard
}

impl Pattern {
    /// Parse a pattern string like "80 79 ?? ?? 8B 54"
    pub fn parse(pattern: &str) -> Option<Self> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        for part in pattern.split_whitespace() {
            if part == "??" || part == "?" {
                bytes.push(0);
                mask.push(false);
            } else {
                let byte = u8::from_str_radix(part, 16).ok()?;
                bytes.push(byte);
                mask.push(true);
            }
        }

        if bytes.is_empty() {
            return None;
        }

        Some(Self { bytes, mask })
    }

    /// Check if pattern matches at the given memory location
    ///
    /// # Safety
    /// Caller must ensure `ptr` points to readable memory of at least `self.len()` bytes.
    #[inline]
    pub unsafe fn matches_at(&self, ptr: *const u8) -> bool {
        for (i, (&pattern_byte, &must_match)) in self.bytes.iter().zip(self.mask.iter()).enumerate()
        {
            if must_match && unsafe { *ptr.add(i) } != pattern_byte {
                return false;
            }
        }
        true
    }

    /// Get the length of the pattern
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

/// Scan a memory region for a pattern
///
/// # Safety
/// Caller must ensure `start` to `start + size` is valid readable memory.
pub unsafe fn scan_region(start: usize, size: usize, pattern: &Pattern) -> Option<usize> {
    if size < pattern.len() {
        return None;
    }

    let end = start + size - pattern.len();
    let mut addr = start;

    while addr <= end {
        if unsafe { pattern.matches_at(addr as *const u8) } {
            return Some(addr);
        }
        addr += 1;
    }

    None
}

/// Scan a module's executable sections for a pattern
///
/// Returns the address of the first match, or None if not found.
pub fn scan_module(module_base: usize, pattern: &Pattern) -> Option<usize> {
    // Initialize system info (not currently used but may be useful later)
    let _page_size = unsafe {
        let mut si = SYSTEM_INFO::default();
        GetSystemInfo(&mut si);
        si.dwPageSize as usize
    };

    let mut addr = module_base;
    let max_scan = 0x10000000; // 256MB max scan range

    while addr < module_base + max_scan {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let result = unsafe {
            VirtualQuery(
                Some(addr as *const _),
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            break;
        }

        // Check if this is a readable code section
        let protect = mbi.Protect;
        let is_readable = protect == PAGE_EXECUTE_READ
            || protect == PAGE_EXECUTE_READWRITE
            || protect == PAGE_READONLY
            || protect == PAGE_READWRITE;

        if is_readable && mbi.RegionSize > 0 {
            let region_start = mbi.BaseAddress as usize;
            let region_size = mbi.RegionSize;

            if let Some(found) = unsafe { scan_region(region_start, region_size, pattern) } {
                return Some(found);
            }
        }

        // Move to next region
        addr = mbi.BaseAddress as usize + mbi.RegionSize;
        if addr < mbi.BaseAddress as usize {
            break; // Overflow protection
        }
    }

    None
}
