//! Checked memory reads and writes for runtime patches.

use std::ffi::c_void;
use std::fmt;
use std::mem::size_of;

use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, VirtualProtect, VirtualQuery,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteState {
    Applied,
    AlreadyApplied,
}

#[derive(Debug)]
pub enum MemoryError {
    EmptyReplacement,
    LengthMismatch {
        expected: usize,
        replacement: usize,
    },
    AddressOverflow {
        address: usize,
        length: usize,
    },
    QueryFailed {
        address: usize,
    },
    NotReadable {
        address: usize,
        protection: u32,
    },
    NotCommitted {
        address: usize,
    },
    CrossesProtectionRegion {
        address: usize,
        length: usize,
    },
    UnexpectedBytes {
        address: usize,
        expected: Vec<u8>,
        replacement: Vec<u8>,
        actual: Vec<u8>,
    },
    Protect {
        address: usize,
        error: String,
    },
    RestoreProtection {
        address: usize,
        error: String,
    },
    FlushInstructionCache {
        address: usize,
        error: String,
    },
    WriteVerification {
        address: usize,
        expected: Vec<u8>,
        actual: Vec<u8>,
    },
}

impl fmt::Display for MemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyReplacement => write!(formatter, "replacement byte sequence is empty"),
            Self::LengthMismatch {
                expected,
                replacement,
            } => write!(
                formatter,
                "expected-byte length {expected} differs from replacement length {replacement}"
            ),
            Self::AddressOverflow { address, length } => write!(
                formatter,
                "memory range 0x{address:08X} + {length} overflows"
            ),
            Self::QueryFailed { address } => {
                write!(formatter, "VirtualQuery failed at 0x{address:08X}")
            }
            Self::NotReadable {
                address,
                protection,
            } => write!(
                formatter,
                "memory at 0x{address:08X} is not readable (protection 0x{protection:X})"
            ),
            Self::NotCommitted { address } => {
                write!(formatter, "memory at 0x{address:08X} is not committed")
            }
            Self::CrossesProtectionRegion { address, length } => write!(
                formatter,
                "write range 0x{address:08X} + {length} crosses a virtual-memory protection region"
            ),
            Self::UnexpectedBytes {
                address,
                expected,
                replacement,
                actual,
            } => write!(
                formatter,
                "unexpected bytes at 0x{address:08X}: expected {} or already-patched {}, found {}",
                format_bytes(expected),
                format_bytes(replacement),
                format_bytes(actual)
            ),
            Self::Protect { address, error } => write!(
                formatter,
                "VirtualProtect failed at 0x{address:08X}: {error}"
            ),
            Self::RestoreProtection { address, error } => write!(
                formatter,
                "restoring memory protection failed at 0x{address:08X}: {error}"
            ),
            Self::FlushInstructionCache { address, error } => write!(
                formatter,
                "FlushInstructionCache failed at 0x{address:08X}: {error}"
            ),
            Self::WriteVerification {
                address,
                expected,
                actual,
            } => write!(
                formatter,
                "write verification failed at 0x{address:08X}: expected {}, found {}",
                format_bytes(expected),
                format_bytes(actual)
            ),
        }
    }
}

impl std::error::Error for MemoryError {}

/// Read bytes after validating every virtual-memory region in the range.
pub fn read_bytes(address: usize, length: usize) -> Result<Vec<u8>, MemoryError> {
    validate_readable_range(address, length)?;

    let mut bytes = vec![0; length];
    if length != 0 {
        unsafe {
            std::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), length);
        }
    }
    Ok(bytes)
}

/// Validate that a destination contains either its original or replacement
/// bytes without modifying memory.
pub fn validate_bytes(
    address: usize,
    expected: &[u8],
    replacement: &[u8],
) -> Result<WriteState, MemoryError> {
    validate_lengths(expected, replacement)?;
    classify_bytes(
        address,
        expected,
        replacement,
        read_bytes(address, expected.len())?,
    )
}

/// Apply an idempotent, expected-byte-guarded memory write.
pub fn write_checked(
    address: usize,
    expected: &[u8],
    replacement: &[u8],
) -> Result<WriteState, MemoryError> {
    validate_lengths(expected, replacement)?;

    match classify_bytes(
        address,
        expected,
        replacement,
        read_bytes(address, expected.len())?,
    )? {
        WriteState::AlreadyApplied => return Ok(WriteState::AlreadyApplied),
        WriteState::Applied => {}
    }

    let pointer = address as *mut u8;
    let length = replacement.len();
    let writable_protection = writable_protection_for_single_region(address, length)?;
    let mut old_protection = 0;

    let protect_result = unsafe {
        VirtualProtect(
            pointer as *const c_void,
            length,
            writable_protection,
            &mut old_protection,
        )
    };
    if protect_result == 0 {
        return Err(MemoryError::Protect {
            address,
            error: std::io::Error::last_os_error().to_string(),
        });
    }

    unsafe {
        std::ptr::copy_nonoverlapping(replacement.as_ptr(), pointer, length);
    }

    let mut ignored_protection = 0;
    let restore_result = unsafe {
        VirtualProtect(
            pointer as *const c_void,
            length,
            old_protection,
            &mut ignored_protection,
        )
    };
    let restore_error = (restore_result == 0).then(|| std::io::Error::last_os_error().to_string());
    let flush_result =
        unsafe { FlushInstructionCache(GetCurrentProcess(), pointer as *const c_void, length) };
    let flush_error = (flush_result == 0).then(|| std::io::Error::last_os_error().to_string());

    if let Some(error) = restore_error {
        return Err(MemoryError::RestoreProtection { address, error });
    }
    if let Some(error) = flush_error {
        return Err(MemoryError::FlushInstructionCache { address, error });
    }

    let actual = read_bytes(address, length)?;
    if actual != replacement {
        return Err(MemoryError::WriteVerification {
            address,
            expected: replacement.to_vec(),
            actual,
        });
    }

    Ok(WriteState::Applied)
}

fn validate_lengths(expected: &[u8], replacement: &[u8]) -> Result<(), MemoryError> {
    if replacement.is_empty() {
        return Err(MemoryError::EmptyReplacement);
    }
    if expected.len() != replacement.len() {
        return Err(MemoryError::LengthMismatch {
            expected: expected.len(),
            replacement: replacement.len(),
        });
    }
    Ok(())
}

fn classify_bytes(
    address: usize,
    expected: &[u8],
    replacement: &[u8],
    actual: Vec<u8>,
) -> Result<WriteState, MemoryError> {
    if actual == replacement {
        Ok(WriteState::AlreadyApplied)
    } else if actual == expected {
        // `Applied` here means a write is required.
        Ok(WriteState::Applied)
    } else {
        Err(MemoryError::UnexpectedBytes {
            address,
            expected: expected.to_vec(),
            replacement: replacement.to_vec(),
            actual,
        })
    }
}

fn validate_readable_range(address: usize, length: usize) -> Result<(), MemoryError> {
    if length == 0 {
        return Ok(());
    }

    let end = address
        .checked_add(length)
        .ok_or(MemoryError::AddressOverflow { address, length })?;
    let mut cursor = address;

    while cursor < end {
        let mut information = MEMORY_BASIC_INFORMATION::default();
        let queried = unsafe {
            VirtualQuery(
                cursor as *const _,
                &mut information,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if queried == 0 {
            return Err(MemoryError::QueryFailed { address: cursor });
        }
        if information.State != MEM_COMMIT {
            return Err(MemoryError::NotCommitted { address: cursor });
        }

        let protection = information.Protect;
        if protection & PAGE_GUARD != 0 || !is_readable_protection(protection) {
            return Err(MemoryError::NotReadable {
                address: cursor,
                protection,
            });
        }

        let region_end = (information.BaseAddress as usize)
            .checked_add(information.RegionSize)
            .ok_or(MemoryError::AddressOverflow {
                address: information.BaseAddress as usize,
                length: information.RegionSize,
            })?;
        if region_end <= cursor {
            return Err(MemoryError::QueryFailed { address: cursor });
        }
        cursor = region_end.min(end);
    }

    Ok(())
}

fn writable_protection_for_single_region(
    address: usize,
    length: usize,
) -> Result<PAGE_PROTECTION_FLAGS, MemoryError> {
    let end = address
        .checked_add(length)
        .ok_or(MemoryError::AddressOverflow { address, length })?;
    let mut information = MEMORY_BASIC_INFORMATION::default();
    let queried = unsafe {
        VirtualQuery(
            address as *const _,
            &mut information,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if queried == 0 {
        return Err(MemoryError::QueryFailed { address });
    }
    if information.State != MEM_COMMIT {
        return Err(MemoryError::NotCommitted { address });
    }

    let protection = information.Protect;
    if protection & PAGE_GUARD != 0 || !is_readable_protection(protection) {
        return Err(MemoryError::NotReadable {
            address,
            protection,
        });
    }

    let region_end = (information.BaseAddress as usize)
        .checked_add(information.RegionSize)
        .ok_or(MemoryError::AddressOverflow {
            address: information.BaseAddress as usize,
            length: information.RegionSize,
        })?;
    if end > region_end {
        return Err(MemoryError::CrossesProtectionRegion { address, length });
    }

    let base = protection & 0xFF;
    if base == PAGE_EXECUTE_READ || base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY
    {
        Ok(PAGE_EXECUTE_READWRITE)
    } else {
        Ok(PAGE_READWRITE)
    }
}

fn is_readable_protection(protection: PAGE_PROTECTION_FLAGS) -> bool {
    let base = protection & 0xFF;
    base == PAGE_READONLY
        || base == PAGE_READWRITE
        || base == PAGE_WRITECOPY
        || base == PAGE_EXECUTE_READ
        || base == PAGE_EXECUTE_READWRITE
        || base == PAGE_EXECUTE_WRITECOPY
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_original_and_patched_bytes() {
        assert_eq!(
            classify_bytes(0x1000, &[0x74, 0x16], &[0xEB, 0x0E], vec![0x74, 0x16]).unwrap(),
            WriteState::Applied
        );
        assert_eq!(
            classify_bytes(0x1000, &[0x74, 0x16], &[0xEB, 0x0E], vec![0xEB, 0x0E]).unwrap(),
            WriteState::AlreadyApplied
        );
    }

    #[test]
    fn rejects_unexpected_bytes() {
        assert!(
            classify_bytes(0x1000, &[0x0A], &[0x14], vec![0x24])
                .unwrap_err()
                .to_string()
                .contains("found 24")
        );
    }

    #[test]
    fn rejects_empty_and_mismatched_replacements() {
        assert!(validate_lengths(&[], &[]).is_err());
        assert!(validate_lengths(&[1], &[1, 2]).is_err());
    }

    #[test]
    fn writes_and_then_recognizes_an_idempotent_patch() {
        let mut memory = vec![0x0A];
        let address = memory.as_mut_ptr() as usize;

        assert_eq!(
            write_checked(address, &[0x0A], &[0x14]).unwrap(),
            WriteState::Applied
        );
        assert_eq!(memory, [0x14]);
        assert_eq!(
            write_checked(address, &[0x0A], &[0x14]).unwrap(),
            WriteState::AlreadyApplied
        );
    }
}
