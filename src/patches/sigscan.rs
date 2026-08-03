//! PE-aware signature scanning for loaded modules.
//!
//! The scanner snapshots validated PE sections once, then searches only the
//! requested section class. It never walks arbitrary address space beyond the
//! module image.

use std::fmt;
use std::mem::size_of;

use portex::reader::Reader;
use portex::{Error as PortexError, MachineType, PEHeaders};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY, VirtualQuery,
};
use windows_sys::Win32::System::ProcessStatus::{K32GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// A parsed byte pattern. `None` entries are wildcards.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pattern {
    bytes: Vec<Option<u8>>,
}

impl Pattern {
    pub fn parse(pattern: &str) -> Result<Self, ScanError> {
        let mut bytes = Vec::new();

        for part in pattern.split_whitespace() {
            if part == "??" || part == "?" {
                bytes.push(None);
            } else {
                let byte = u8::from_str_radix(part, 16)
                    .map_err(|_| ScanError::InvalidPattern(pattern.to_owned()))?;
                bytes.push(Some(byte));
            }
        }

        if bytes.is_empty() {
            return Err(ScanError::InvalidPattern(pattern.to_owned()));
        }

        Ok(Self { bytes })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    fn matches(&self, candidate: &[u8]) -> bool {
        self.bytes
            .iter()
            .zip(candidate)
            .all(|(expected, actual)| expected.is_none_or(|expected| expected == *actual))
    }

    fn find_offsets(&self, bytes: &[u8]) -> Vec<usize> {
        if bytes.len() < self.len() {
            return Vec::new();
        }

        bytes
            .windows(self.len())
            .enumerate()
            .filter_map(|(offset, candidate)| self.matches(candidate).then_some(offset))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanScope {
    Code,
    ReadOnlyData,
}

#[derive(Clone, Debug)]
struct PeSection {
    name: String,
    rva: usize,
    size: usize,
    executable: bool,
    readable: bool,
    writable: bool,
}

impl PeSection {
    fn is_in_scope(&self, scope: ScanScope) -> bool {
        match scope {
            ScanScope::Code => self.executable,
            ScanScope::ReadOnlyData => self.readable && !self.writable && !self.executable,
        }
    }
}

#[derive(Debug)]
struct LoadedSection {
    metadata: PeSection,
    bytes: Vec<u8>,
}

/// A validated snapshot of the readable sections in a loaded PE image.
#[derive(Debug)]
pub struct ModuleImage {
    base: usize,
    size: usize,
    sections: Vec<LoadedSection>,
}

pub(super) struct FileMappedModule {
    pub(super) image: ModuleImage,
    _mapping: Vec<u8>,
}

impl ModuleImage {
    /// Snapshot a loaded module's validated PE sections.
    ///
    /// # Safety
    ///
    /// `module` must be a live module handle in the current process.
    pub unsafe fn from_module(module: HMODULE) -> Result<Self, ScanError> {
        let mut module_info = MODULEINFO::default();
        let module_information_result = unsafe {
            K32GetModuleInformation(
                GetCurrentProcess(),
                module,
                &mut module_info,
                size_of::<MODULEINFO>() as u32,
            )
        };
        if module_information_result == 0 {
            return Err(ScanError::ModuleInformation(
                std::io::Error::last_os_error().to_string(),
            ));
        }

        let base = module_info.lpBaseOfDll as usize;
        let size = module_info.SizeOfImage as usize;
        if base == 0 || size == 0 {
            return Err(ScanError::InvalidPe(
                "module information returned an empty image".to_owned(),
            ));
        }

        let reader = ValidatedModuleReader { base, size };
        let headers = PEHeaders::read_from(&reader, 0).map_err(|error| {
            ScanError::InvalidPe(format!("Portex rejected the loaded headers: {error}"))
        })?;
        let sections = validate_pe_sections(headers, size)?;

        let mut loaded_sections = Vec::new();
        for section in sections {
            if section.size == 0 || (!section.readable && !section.executable) {
                continue;
            }

            let address = base
                .checked_add(section.rva)
                .ok_or_else(|| ScanError::InvalidPe("section address overflow".to_owned()))?;
            validate_readable_range(address, section.size).map_err(|reason| {
                ScanError::UnreadableSection {
                    name: section.name.clone(),
                    reason,
                }
            })?;

            loaded_sections.push(LoadedSection {
                bytes: copy_memory(address, section.size),
                metadata: section,
            });
        }

        if loaded_sections.is_empty() {
            return Err(ScanError::InvalidPe(
                "PE image has no readable code or data sections".to_owned(),
            ));
        }

        Ok(Self {
            base,
            size,
            sections: loaded_sections,
        })
    }

    pub fn base(&self) -> usize {
        self.base
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Return every match in the selected PE section class.
    pub fn scan(&self, pattern: &Pattern, scope: ScanScope) -> Vec<usize> {
        let mut matches = Vec::new();

        for section in &self.sections {
            if !section.metadata.is_in_scope(scope) {
                continue;
            }

            let Some(section_address) = self.base.checked_add(section.metadata.rva) else {
                continue;
            };
            for offset in pattern.find_offsets(&section.bytes) {
                if let Some(address) = section_address.checked_add(offset) {
                    matches.push(address);
                }
            }
        }

        matches
    }

    pub fn address_from_rva(
        &self,
        rva: usize,
        length: usize,
        scope: ScanScope,
    ) -> Result<usize, ScanError> {
        let end = rva
            .checked_add(length)
            .ok_or_else(|| ScanError::InvalidPe("RVA range overflow".to_owned()))?;
        if end > self.size {
            return Err(ScanError::AddressOutsideImage { rva, length });
        }

        let in_section = self.sections.iter().any(|section| {
            if !section.metadata.is_in_scope(scope) {
                return false;
            }

            let section_start = section.metadata.rva;
            let Some(section_end) = section_start.checked_add(section.metadata.size) else {
                return false;
            };
            rva >= section_start && end <= section_end
        });

        if !in_section {
            return Err(ScanError::AddressOutsideScope { rva, length, scope });
        }

        self.base
            .checked_add(rva)
            .ok_or_else(|| ScanError::InvalidPe("RVA address overflow".to_owned()))
    }

    pub fn contains_relative_target(
        &self,
        match_address: usize,
        target_address: usize,
        length: usize,
        scope: ScanScope,
    ) -> bool {
        let Some(match_rva) = match_address.checked_sub(self.base) else {
            return false;
        };
        let Some(target_rva) = target_address.checked_sub(self.base) else {
            return false;
        };
        let Some(target_end) = target_rva.checked_add(length) else {
            return false;
        };

        self.sections.iter().any(|section| {
            if !section.metadata.is_in_scope(scope) {
                return false;
            }

            let section_start = section.metadata.rva;
            let Some(section_end) = section_start.checked_add(section.metadata.size) else {
                return false;
            };

            match_rva >= section_start
                && match_rva < section_end
                && target_rva >= section_start
                && target_end <= section_end
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test_section(
        base: usize,
        rva: usize,
        bytes: Vec<u8>,
        scope: ScanScope,
    ) -> Self {
        let (name, executable, readable, writable) = match scope {
            ScanScope::Code => (".text", true, true, false),
            ScanScope::ReadOnlyData => (".rdata", false, true, false),
        };
        let size = bytes.len();

        Self {
            base,
            size: rva + size,
            sections: vec![LoadedSection {
                metadata: PeSection {
                    name: name.to_owned(),
                    rva,
                    size,
                    executable,
                    readable,
                    writable,
                },
                bytes,
            }],
        }
    }

    /// Parse an on-disk PE with Portex and reconstruct its loaded section
    /// layout in ordinary heap memory without loading or executing the image.
    pub(super) fn from_pe_file(file: &[u8]) -> Result<FileMappedModule, ScanError> {
        let headers = PEHeaders::from_slice(file)
            .map_err(|error| ScanError::InvalidPe(format!("Portex rejected the file: {error}")))?;
        let image_size = headers.optional_header.size_of_image() as usize;
        let sections = validate_pe_sections(headers.clone(), image_size)?;
        let mut mapping = vec![0; image_size];

        for (section, header) in sections.iter().zip(&headers.section_headers) {
            let raw_size = header.size_of_raw_data as usize;
            if raw_size == 0 {
                continue;
            }

            let raw_start = header.pointer_to_raw_data as usize;
            if raw_start == 0 {
                return Err(ScanError::InvalidPe(format!(
                    "section {:?} has raw data at file offset zero",
                    section.name
                )));
            }
            let raw_end = raw_start.checked_add(raw_size).ok_or_else(|| {
                ScanError::InvalidPe(format!("section {:?} raw range overflow", section.name))
            })?;
            if raw_end > file.len() {
                return Err(ScanError::InvalidPe(format!(
                    "section {:?} raw data ends outside the file",
                    section.name
                )));
            }

            let mapped_end = section.rva.checked_add(raw_size).ok_or_else(|| {
                ScanError::InvalidPe(format!("section {:?} mapped range overflow", section.name))
            })?;
            if mapped_end > mapping.len() || raw_size > section.size {
                return Err(ScanError::InvalidPe(format!(
                    "section {:?} raw data ends outside its mapped range",
                    section.name
                )));
            }

            mapping[section.rva..mapped_end].copy_from_slice(&file[raw_start..raw_end]);
        }

        let base = mapping.as_mut_ptr() as usize;
        let loaded_sections = sections
            .into_iter()
            .filter(|section| section.size != 0 && (section.readable || section.executable))
            .map(|section| LoadedSection {
                bytes: mapping[section.rva..section.rva + section.size].to_vec(),
                metadata: section,
            })
            .collect::<Vec<_>>();

        if loaded_sections.is_empty() {
            return Err(ScanError::InvalidPe(
                "PE image has no readable code or data sections".to_owned(),
            ));
        }

        Ok(FileMappedModule {
            image: Self {
                base,
                size: image_size,
                sections: loaded_sections,
            },
            _mapping: mapping,
        })
    }
}

#[derive(Debug)]
pub enum ScanError {
    InvalidPattern(String),
    ModuleInformation(String),
    InvalidPe(String),
    UnreadableSection {
        name: String,
        reason: String,
    },
    AddressOutsideImage {
        rva: usize,
        length: usize,
    },
    AddressOutsideScope {
        rva: usize,
        length: usize,
        scope: ScanScope,
    },
}

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPattern(pattern) => write!(formatter, "invalid signature {pattern:?}"),
            Self::ModuleInformation(error) => {
                write!(formatter, "could not query module information: {error}")
            }
            Self::InvalidPe(reason) => write!(formatter, "invalid PE image: {reason}"),
            Self::UnreadableSection { name, reason } => {
                write!(formatter, "PE section {name:?} is not readable: {reason}")
            }
            Self::AddressOutsideImage { rva, length } => write!(
                formatter,
                "RVA 0x{rva:08X} (length {length}) is outside the module image"
            ),
            Self::AddressOutsideScope { rva, length, scope } => write!(
                formatter,
                "RVA 0x{rva:08X} (length {length}) is outside {scope:?} sections"
            ),
        }
    }
}

impl std::error::Error for ScanError {}

/// A Portex reader that bounds every request to the loaded image and validates
/// the corresponding virtual-memory pages before copying.
struct ValidatedModuleReader {
    base: usize,
    size: usize,
}

impl Reader for ValidatedModuleReader {
    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> portex::Result<usize> {
        let Ok(offset) = usize::try_from(offset) else {
            return Ok(0);
        };
        let Some(available) = self.size.checked_sub(offset) else {
            return Ok(0);
        };
        let length = buffer.len().min(available);
        if length == 0 {
            return Ok(0);
        }

        let address = self
            .base
            .checked_add(offset)
            .ok_or_else(|| PortexError::generic("loaded-module address overflow"))?;
        validate_readable_range(address, length).map_err(|reason| {
            PortexError::generic(format!(
                "loaded-module read at offset 0x{offset:X} is unsafe: {reason}"
            ))
        })?;

        unsafe {
            std::ptr::copy_nonoverlapping(address as *const u8, buffer.as_mut_ptr(), length);
        }
        Ok(length)
    }

    fn size(&self) -> Option<u64> {
        Some(self.size as u64)
    }
}

#[cfg(test)]
fn parse_pe_sections(headers: &[u8], module_size: usize) -> Result<Vec<PeSection>, ScanError> {
    let parsed = PEHeaders::from_slice(headers)
        .map_err(|error| ScanError::InvalidPe(format!("Portex rejected the headers: {error}")))?;
    validate_pe_sections(parsed, module_size)
}

fn validate_pe_sections(
    parsed: PEHeaders,
    module_size: usize,
) -> Result<Vec<PeSection>, ScanError> {
    if parsed.is_64bit() {
        return Err(ScanError::InvalidPe(
            "Dunia.dll is not a 32-bit PE image".to_owned(),
        ));
    }
    if parsed.coff_header.machine_type() != Some(MachineType::I386) {
        return Err(ScanError::InvalidPe(format!(
            "Dunia.dll has unsupported machine type 0x{:04X}",
            parsed.coff_header.machine
        )));
    }
    if !parsed.coff_header.is_dll() {
        return Err(ScanError::InvalidPe(
            "loaded image is not marked as a DLL".to_owned(),
        ));
    }

    let number_of_sections = parsed.section_headers.len();
    if number_of_sections == 0 || number_of_sections > 96 {
        return Err(ScanError::InvalidPe(format!(
            "invalid section count {number_of_sections}"
        )));
    }

    let image_size = parsed.optional_header.size_of_image() as usize;
    if image_size == 0 || image_size != module_size {
        return Err(ScanError::InvalidPe(format!(
            "header SizeOfImage 0x{image_size:X} differs from mapped size 0x{module_size:X}"
        )));
    }

    let mut sections = Vec::with_capacity(number_of_sections);
    for header in parsed.section_headers {
        let name = header.name_str().into_owned();
        let size = header.virtual_size.max(header.size_of_raw_data) as usize;
        let rva = header.virtual_address as usize;

        let end = rva
            .checked_add(size)
            .ok_or_else(|| ScanError::InvalidPe(format!("section {name:?} range overflow")))?;
        if end > image_size {
            return Err(ScanError::InvalidPe(format!(
                "section {name:?} ends outside SizeOfImage"
            )));
        }

        sections.push(PeSection {
            name,
            rva,
            size,
            executable: header.is_executable(),
            readable: header.is_readable(),
            writable: header.is_writable(),
        });
    }

    for (index, section) in sections.iter().enumerate() {
        if section.size == 0 {
            continue;
        }
        let section_end = section.rva + section.size;

        for other in sections.iter().skip(index + 1) {
            if other.size == 0 {
                continue;
            }
            let other_end = other.rva + other.size;
            if section.rva < other_end && other.rva < section_end {
                return Err(ScanError::InvalidPe(format!(
                    "sections {:?} and {:?} overlap in memory",
                    section.name, other.name
                )));
            }
        }
    }

    Ok(sections)
}

fn validate_readable_range(address: usize, length: usize) -> Result<(), String> {
    if length == 0 {
        return Ok(());
    }

    let end = address
        .checked_add(length)
        .ok_or_else(|| "address range overflow".to_owned())?;
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
            return Err(format!("VirtualQuery failed at 0x{cursor:08X}"));
        }

        validate_region(&information)?;
        let region_end = (information.BaseAddress as usize)
            .checked_add(information.RegionSize)
            .ok_or_else(|| "memory-region range overflow".to_owned())?;
        if region_end <= cursor {
            return Err("VirtualQuery did not advance".to_owned());
        }
        cursor = region_end.min(end);
    }

    Ok(())
}

fn validate_region(information: &MEMORY_BASIC_INFORMATION) -> Result<(), String> {
    if information.State != MEM_COMMIT {
        return Err("memory is not committed".to_owned());
    }

    let protection = information.Protect;
    if protection & PAGE_GUARD != 0 || !is_readable_protection(protection) {
        return Err(format!(
            "memory protection 0x{:X} is not readable",
            protection
        ));
    }

    Ok(())
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

fn copy_memory(address: usize, length: usize) -> Vec<u8> {
    let mut bytes = vec![0; length];
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), length);
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wildcards_and_finds_overlapping_matches() {
        let pattern = Pattern::parse("AA ?? AA").unwrap();
        assert_eq!(pattern.find_offsets(&[0xAA, 1, 0xAA, 2, 0xAA]), [0, 2]);
    }

    #[test]
    fn rejects_empty_and_invalid_patterns() {
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("GG").is_err());
    }

    #[test]
    fn parses_and_classifies_pe_sections() {
        let headers = synthetic_pe_headers();
        let sections = parse_pe_sections(&headers, 0x3000).unwrap();

        assert_eq!(sections.len(), 2);
        assert_eq!(sections[0].name, ".text");
        assert!(sections[0].is_in_scope(ScanScope::Code));
        assert!(!sections[0].is_in_scope(ScanScope::ReadOnlyData));
        assert_eq!(sections[1].name, ".rdata");
        assert!(sections[1].is_in_scope(ScanScope::ReadOnlyData));
    }

    #[test]
    fn portex_reads_headers_through_validated_module_memory() {
        let headers = synthetic_pe_headers();
        let reader = ValidatedModuleReader {
            base: headers.as_ptr() as usize,
            size: headers.len(),
        };

        let parsed = PEHeaders::read_from(&reader, 0).unwrap();

        assert_eq!(parsed.coff_header.machine_type(), Some(MachineType::I386));
        assert_eq!(parsed.section_headers.len(), 2);
    }

    #[test]
    fn rejects_sections_outside_the_image() {
        let mut headers = synthetic_pe_headers();
        let section_table = 0x80 + 24 + 0xE0;
        put_u32(&mut headers, section_table + 8, 0x2001);

        assert!(parse_pe_sections(&headers, 0x3000).is_err());
    }

    #[test]
    fn rejects_overlapping_sections() {
        let mut headers = synthetic_pe_headers();
        let section_table = 0x80 + 24 + 0xE0;
        let rdata = section_table + portex::SectionHeader::SIZE;
        put_u32(&mut headers, rdata + 12, 0x1080);

        assert!(parse_pe_sections(&headers, 0x3000).is_err());
    }

    #[test]
    fn relative_targets_must_stay_in_the_matched_section() {
        let image = ModuleImage::for_test_section(0x1000, 0x200, vec![0; 4], ScanScope::Code);

        assert!(image.contains_relative_target(0x1201, 0x1203, 1, ScanScope::Code));
        assert!(!image.contains_relative_target(0x1201, 0x1203, 2, ScanScope::Code));
        assert!(!image.contains_relative_target(0x1201, 0x1203, 1, ScanScope::ReadOnlyData));
    }

    fn synthetic_pe_headers() -> Vec<u8> {
        let mut headers = vec![0; 0x400];
        put_u16(&mut headers, 0, 0x5A4D);
        put_u32(&mut headers, 0x3C, 0x80);
        put_u32(&mut headers, 0x80, 0x0000_4550);
        put_u16(&mut headers, 0x80 + 4, MachineType::I386 as u16);
        put_u16(&mut headers, 0x80 + 6, 2);
        put_u16(&mut headers, 0x80 + 20, 0xE0);
        put_u16(
            &mut headers,
            0x80 + 22,
            portex::coff::characteristics::EXECUTABLE_IMAGE
                | portex::coff::characteristics::MACHINE_32BIT
                | portex::coff::characteristics::DLL,
        );

        let optional = 0x80 + 24;
        put_u16(&mut headers, optional, 0x010B);
        put_u32(&mut headers, optional + 56, 0x3000);

        let section_table = optional + 0xE0;
        headers[section_table..section_table + 5].copy_from_slice(b".text");
        put_u32(&mut headers, section_table + 8, 0x100);
        put_u32(&mut headers, section_table + 12, 0x1000);
        put_u32(&mut headers, section_table + 16, 0x100);
        put_u32(
            &mut headers,
            section_table + 36,
            portex::section::characteristics::CODE
                | portex::section::characteristics::EXECUTE
                | portex::section::characteristics::READ,
        );

        let rdata = section_table + portex::SectionHeader::SIZE;
        headers[rdata..rdata + 6].copy_from_slice(b".rdata");
        put_u32(&mut headers, rdata + 8, 0x80);
        put_u32(&mut headers, rdata + 12, 0x2000);
        put_u32(&mut headers, rdata + 16, 0x80);
        put_u32(
            &mut headers,
            rdata + 36,
            portex::section::characteristics::READ,
        );

        headers
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
