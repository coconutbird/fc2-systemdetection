//! Validated runtime patches for `Dunia.dll`.
//!
//! Enabled patches are resolved and byte-validated before any write occurs.
//! Signature searches are restricted to Portex-parsed PE sections, and every
//! target accepts only its known original or already-patched bytes.

mod config;
mod memory;
mod offline;
mod sigscan;

pub use offline::{DuniaFileValidation, OfflinePatchState, ValidatedPatch, validate_dunia_file};

use std::ffi::OsString;
use std::fmt;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use config::{ConfigLoad, ConfigSource, PatchConfig};
use memory::{MemoryError, WriteState, validate_bytes, write_checked};
use sigscan::{ModuleImage, Pattern, ScanError, ScanScope};
use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::Diagnostics::Debug::OutputDebugStringW;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleA};

const STEAM_DUNIA_FILE_SIZE: u64 = 20_183_176;
const RETAIL_DUNIA_FILE_SIZE: u64 = 19_412_104;
const UBISOFT_DUNIA_FILE_SIZE: u64 = 20_184_168;

// FoxAhead's Retail/GOG 1.03 target is VA 0x10048987 at preferred image base
// 0x10000000. Use the RVA so relocation/ASLR does not affect the target.
const RETAIL_PREDECESSOR_RVA: usize = 0x0004_8987;

const STEAM_NO_BLINK_RVAS: [usize; 3] = [0x00E4_9D08, 0x00E1_15B8, 0x00E9_33B3];
const RETAIL_NO_BLINK_RVAS: [usize; 3] = [0x00DC_1A94, 0x00D8_B3B0, 0x00E0_AFC2];

mod signatures {
    pub const JACKAL_TAPES: &str = "80 7E 74 00 75 ?? 3B CA 75";

    // The final opcode is a wildcard so an already-patched JMP remains
    // discoverable. Destination-byte validation accepts only JNZ or JMP.
    pub const DEVMODE_ALWAYS_ON: &str = "80 79 ?? 00 8B 54 24 ?? ??";

    // Both branch bytes are wildcards for idempotent discovery.
    pub const PREDECESSOR_TAPES_STEAM: &str = "8B 49 0C 85 C9 ?? ?? 8B 44 24";

    // This prologue is qualified by checking the known return instruction at
    // +0x69. Multiple raw prologue matches are safe because exactly one
    // validated destination is required.
    pub const MACHETES: &str = "83 EC ?? 53 8D 44 24 ?? 50 68";

    // Mutation bytes are wildcards so already-patched strings remain
    // discoverable and can be reported as idempotently applied.
    pub const MESH_HIGHLIGHT: &str = "4D 65 73 68 ?? 48 69 67 68 6C 69 67 68 74";
    pub const ARCH_BLINK: &str = "61 72 63 68 42 6C 69 6E ??";
    pub const SAVE_DISK: &str = "67 61 64 67 65 74 73 2E 4F 62 6A 65 63 74 69 76 65 49 63 6F 6E 73 2E 53 61 76 65 44 69 73 6B ??";
}

/// Apply the configured patch set once runtime initialization is outside the
/// Windows loader lock.
pub fn initialize(self_module: HMODULE) {
    let (config, configuration, configuration_warnings) = load_patch_config(self_module);
    let mut report = run(config);
    report.configuration = Some(configuration);
    report.warnings = configuration_warnings;
    emit_report(self_module, &report.to_string());
}

fn load_patch_config(self_module: HMODULE) -> (PatchConfig, String, Vec<String>) {
    let dll_path = match module_path(self_module) {
        Ok(path) => path,
        Err(error) => {
            return (
                PatchConfig::default(),
                format!("DLL path unavailable; using defaults ({error})"),
                Vec::new(),
            );
        }
    };
    let Some(directory) = dll_path.parent() else {
        return (
            PatchConfig::default(),
            "DLL directory unavailable; using defaults".to_owned(),
            Vec::new(),
        );
    };

    let ConfigLoad {
        config,
        path,
        source,
        warnings,
    } = ConfigLoad::load(directory.join("fc2-systemdetection.ini"));
    let description = match source {
        ConfigSource::Loaded => format!("loaded {}", path.display()),
        ConfigSource::MissingUsingDefaults => {
            format!("{} not found; using defaults", path.display())
        }
        ConfigSource::ReadFailedUsingDefaults(error) => {
            format!(
                "could not read {}; using defaults ({error})",
                path.display()
            )
        }
    };

    (config, description, warnings)
}

fn run(config: PatchConfig) -> PatchReport {
    let mut report = PatchReport::new();

    let dunia = unsafe { GetModuleHandleA(c"Dunia.dll".as_ptr() as *const u8) };
    if dunia.is_null() {
        report.fail_enabled(
            &config,
            format!(
                "Dunia.dll is not loaded: {}",
                std::io::Error::last_os_error()
            ),
        );
        return report;
    }

    let image = match unsafe { ModuleImage::from_module(dunia) } {
        Ok(image) => image,
        Err(error) => {
            report.fail_enabled(&config, format!("could not inspect Dunia.dll: {error}"));
            return report;
        }
    };

    report.image = Some(format!(
        "base=0x{:08X}, SizeOfImage=0x{:X}",
        image.base(),
        image.size()
    ));

    let build = detect_build(dunia);
    report.build = Some(build.to_string());

    // Build and validate every enabled plan before applying any plan. This
    // prevents one patch from changing a later patch's signature or guard.
    let prepared = vec![
        prepare_patch("jackal_tapes", config.jackal_tapes, || {
            plan_jackal_tapes(&image)
        }),
        prepare_patch("devmode_always_on", config.devmode_always_on, || {
            plan_devmode_always_on(&image)
        }),
        prepare_patch("predecessor_tapes", config.predecessor_tapes, || {
            plan_predecessor_tapes(&image, &build)
        }),
        prepare_patch("machetes", config.machetes, || plan_machetes(&image)),
        prepare_patch("no_blinking_items", config.no_blinking_items, || {
            plan_no_blinking_items(&image, &build)
        }),
    ];

    report.outcomes = prepared.into_iter().map(PreparedPatch::apply).collect();
    report
}

fn plan_jackal_tapes(image: &ModuleImage) -> Result<PatchPlan, PatchError> {
    let target = find_signature_target(
        image,
        signatures::JACKAL_TAPES,
        ScanScope::Code,
        5,
        &[0x0A],
        &[0x14],
    )?;
    PatchPlan::single(target, &[0x0A], &[0x14])
}

fn plan_devmode_always_on(image: &ModuleImage) -> Result<PatchPlan, PatchError> {
    let target = find_signature_target(
        image,
        signatures::DEVMODE_ALWAYS_ON,
        ScanScope::Code,
        8,
        &[0x75],
        &[0xEB],
    )?;
    PatchPlan::single(target, &[0x75], &[0xEB])
}

fn plan_predecessor_tapes(
    image: &ModuleImage,
    build: &DuniaBuild,
) -> Result<PatchPlan, PatchError> {
    match build {
        DuniaBuild::Retail => {
            let target = image.address_from_rva(RETAIL_PREDECESSOR_RVA, 2, ScanScope::Code)?;
            PatchPlan::single(target, &[0x8A, 0xC3], &[0xB0, 0x01])
        }
        DuniaBuild::Steam | DuniaBuild::Ubisoft | DuniaBuild::Unknown { .. } => {
            let target = find_signature_target(
                image,
                signatures::PREDECESSOR_TAPES_STEAM,
                ScanScope::Code,
                5,
                &[0x74, 0x16],
                &[0xEB, 0x0E],
            )?;
            PatchPlan::single(target, &[0x74, 0x16], &[0xEB, 0x0E])
        }
    }
}

fn plan_machetes(image: &ModuleImage) -> Result<PatchPlan, PatchError> {
    let target = find_signature_target(
        image,
        signatures::MACHETES,
        ScanScope::Code,
        0x69,
        &[0x8A, 0xC3],
        &[0xB0, 0x01],
    )?;
    PatchPlan::single(target, &[0x8A, 0xC3], &[0xB0, 0x01])
}

fn plan_no_blinking_items(
    image: &ModuleImage,
    build: &DuniaBuild,
) -> Result<PatchPlan, PatchError> {
    let known_rvas = match build {
        DuniaBuild::Steam | DuniaBuild::Ubisoft => Some(STEAM_NO_BLINK_RVAS),
        DuniaBuild::Retail => Some(RETAIL_NO_BLINK_RVAS),
        DuniaBuild::Unknown { .. } => None,
    };
    if let Some([mesh_rva, arch_rva, save_rva]) = known_rvas {
        return PatchPlan::new(vec![
            checked_known_signature_write(
                image,
                signatures::MESH_HIGHLIGHT,
                ScanScope::ReadOnlyData,
                mesh_rva,
                4,
                b"_",
                b".",
            )?,
            checked_known_signature_write(
                image,
                signatures::ARCH_BLINK,
                ScanScope::ReadOnlyData,
                arch_rva,
                8,
                b"k",
                b".",
            )?,
            checked_known_signature_write(
                image,
                signatures::SAVE_DISK,
                ScanScope::ReadOnlyData,
                save_rva,
                31,
                b"\0",
                b".",
            )?,
        ]);
    }

    let mesh_highlight = find_signature_target(
        image,
        signatures::MESH_HIGHLIGHT,
        ScanScope::ReadOnlyData,
        4,
        b"_",
        b".",
    )?;
    let arch_blink = find_signature_target(
        image,
        signatures::ARCH_BLINK,
        ScanScope::ReadOnlyData,
        8,
        b"k",
        b".",
    )?;
    let save_disk = find_signature_target(
        image,
        signatures::SAVE_DISK,
        ScanScope::ReadOnlyData,
        31,
        b"\0",
        b".",
    )?;

    PatchPlan::new(vec![
        CheckedWrite::validated(mesh_highlight, b"_", b".")?,
        CheckedWrite::validated(arch_blink, b"k", b".")?,
        CheckedWrite::validated(save_disk, b"\0", b".")?,
    ])
}

/// Validate both a known-build RVA and the complete signature context around
/// it. This avoids treating common single-byte guards such as NUL as
/// sufficient identification.
fn checked_known_signature_write(
    image: &ModuleImage,
    signature: &str,
    scope: ScanScope,
    target_rva: usize,
    target_offset: usize,
    expected: &'static [u8],
    replacement: &'static [u8],
) -> Result<CheckedWrite, PatchError> {
    let pattern = Pattern::parse(signature)?;
    let start_rva =
        target_rva
            .checked_sub(target_offset)
            .ok_or_else(|| PatchError::NoValidatedTarget {
                signature: signature.to_owned(),
                raw_matches: 0,
                reasons: vec![format!(
                    "known target RVA 0x{target_rva:08X} precedes offset {target_offset}"
                )],
            })?;
    let expected_start = image.address_from_rva(start_rva, pattern.len(), scope)?;
    let matches = image.scan(&pattern, scope);
    if !matches.contains(&expected_start) {
        return Err(PatchError::NoValidatedTarget {
            signature: signature.to_owned(),
            raw_matches: matches.len(),
            reasons: vec![format!(
                "no matching context at known start RVA 0x{start_rva:08X}"
            )],
        });
    }

    let target = image.address_from_rva(target_rva, expected.len(), scope)?;
    CheckedWrite::validated(target, expected, replacement)
}

/// Resolve a single destination by combining a section-scoped signature with
/// destination-byte validation.
fn find_signature_target(
    image: &ModuleImage,
    signature: &str,
    scope: ScanScope,
    target_offset: usize,
    expected: &'static [u8],
    replacement: &'static [u8],
) -> Result<usize, PatchError> {
    let pattern = Pattern::parse(signature)?;
    let raw_matches = image.scan(&pattern, scope);
    if raw_matches.is_empty() {
        return Err(PatchError::SignatureNotFound {
            signature: signature.to_owned(),
            scope,
        });
    }

    let mut accepted = Vec::new();
    let mut rejected = Vec::new();

    for start in &raw_matches {
        let Some(target) = start.checked_add(target_offset) else {
            rejected.push(format!("match 0x{start:08X}: target address overflow"));
            continue;
        };

        if !image.contains_relative_target(*start, target, expected.len(), scope) {
            rejected.push(format!(
                "match 0x{start:08X}: target 0x{target:08X} leaves its matched PE section"
            ));
            continue;
        }

        match validate_bytes(target, expected, replacement) {
            Ok(_) => accepted.push(target),
            Err(error) => rejected.push(error.to_string()),
        }
    }

    match accepted.as_slice() {
        [target] => Ok(*target),
        [] => Err(PatchError::NoValidatedTarget {
            signature: signature.to_owned(),
            raw_matches: raw_matches.len(),
            reasons: rejected,
        }),
        _ => Err(PatchError::AmbiguousTarget {
            signature: signature.to_owned(),
            addresses: accepted,
        }),
    }
}

fn prepare_patch(
    name: &'static str,
    enabled: bool,
    build: impl FnOnce() -> Result<PatchPlan, PatchError>,
) -> PreparedPatch {
    if enabled {
        match build() {
            Ok(plan) => PreparedPatch::Ready { name, plan },
            Err(error) => PreparedPatch::Failed { name, error },
        }
    } else {
        PreparedPatch::Disabled { name }
    }
}

#[derive(Debug)]
struct PatchPlan {
    writes: Vec<CheckedWrite>,
}

impl PatchPlan {
    fn single(
        address: usize,
        expected: &'static [u8],
        replacement: &'static [u8],
    ) -> Result<Self, PatchError> {
        Self::new(vec![CheckedWrite::validated(
            address,
            expected,
            replacement,
        )?])
    }

    fn new(writes: Vec<CheckedWrite>) -> Result<Self, PatchError> {
        if writes.is_empty() {
            return Err(PatchError::EmptyPlan);
        }
        Ok(Self { writes })
    }

    fn apply(self) -> Result<WriteState, PatchError> {
        let mut applied = 0;
        let mut already_applied = 0;
        let mut applied_writes = Vec::new();

        for write in self.writes {
            match write.apply() {
                Ok(WriteState::Applied) => {
                    applied += 1;
                    applied_writes.push(write);
                }
                Ok(WriteState::AlreadyApplied) => already_applied += 1,
                Err(error) => {
                    let rollback_errors = applied_writes
                        .into_iter()
                        .rev()
                        .filter_map(|applied_write| applied_write.rollback().err())
                        .collect::<Vec<_>>();

                    return if rollback_errors.is_empty() {
                        Err(error)
                    } else {
                        Err(PatchError::PartialWrite {
                            applied,
                            error: Box::new(error),
                            rollback_errors,
                        })
                    };
                }
            }
        }

        if applied == 0 && already_applied != 0 {
            Ok(WriteState::AlreadyApplied)
        } else {
            Ok(WriteState::Applied)
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct CheckedWrite {
    address: usize,
    expected: &'static [u8],
    replacement: &'static [u8],
}

impl CheckedWrite {
    fn validated(
        address: usize,
        expected: &'static [u8],
        replacement: &'static [u8],
    ) -> Result<Self, PatchError> {
        validate_bytes(address, expected, replacement)?;
        Ok(Self {
            address,
            expected,
            replacement,
        })
    }

    fn apply(self) -> Result<WriteState, PatchError> {
        Ok(write_checked(
            self.address,
            self.expected,
            self.replacement,
        )?)
    }

    fn rollback(self) -> Result<WriteState, PatchError> {
        Ok(write_checked(
            self.address,
            self.replacement,
            self.expected,
        )?)
    }
}

#[derive(Debug)]
enum PreparedPatch {
    Disabled {
        name: &'static str,
    },
    Ready {
        name: &'static str,
        plan: PatchPlan,
    },
    Failed {
        name: &'static str,
        error: PatchError,
    },
}

impl PreparedPatch {
    fn apply(self) -> PatchOutcome {
        match self {
            Self::Disabled { name } => PatchOutcome {
                name,
                status: PatchStatus::Disabled,
            },
            Self::Failed { name, error } => PatchOutcome {
                name,
                status: PatchStatus::Failed(error.to_string()),
            },
            Self::Ready { name, plan } => PatchOutcome {
                name,
                status: match plan.apply() {
                    Ok(WriteState::Applied) => PatchStatus::Applied,
                    Ok(WriteState::AlreadyApplied) => PatchStatus::AlreadyApplied,
                    Err(error) => PatchStatus::Failed(error.to_string()),
                },
            },
        }
    }
}

#[derive(Debug)]
enum PatchError {
    Scan(ScanError),
    Memory(MemoryError),
    SignatureNotFound {
        signature: String,
        scope: ScanScope,
    },
    NoValidatedTarget {
        signature: String,
        raw_matches: usize,
        reasons: Vec<String>,
    },
    AmbiguousTarget {
        signature: String,
        addresses: Vec<usize>,
    },
    EmptyPlan,
    PartialWrite {
        applied: usize,
        error: Box<PatchError>,
        rollback_errors: Vec<PatchError>,
    },
}

impl fmt::Display for PatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan(error) => error.fmt(formatter),
            Self::Memory(error) => error.fmt(formatter),
            Self::SignatureNotFound { signature, scope } => {
                write!(
                    formatter,
                    "signature {signature:?} was not found in {scope:?} sections"
                )
            }
            Self::NoValidatedTarget {
                signature,
                raw_matches,
                reasons,
            } => {
                write!(
                    formatter,
                    "signature {signature:?} had {raw_matches} raw match(es), but no guarded target"
                )?;
                if !reasons.is_empty() {
                    write!(formatter, ": {}", reasons.join("; "))?;
                }
                Ok(())
            }
            Self::AmbiguousTarget {
                signature,
                addresses,
            } => write!(
                formatter,
                "signature {signature:?} resolved to multiple guarded targets: {}",
                addresses
                    .iter()
                    .map(|address| format!("0x{address:08X}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::EmptyPlan => write!(formatter, "patch plan contains no writes"),
            Self::PartialWrite {
                applied,
                error,
                rollback_errors,
            } => write!(
                formatter,
                "patch failed after {applied} write(s), and rollback was incomplete: {error}; rollback error(s): {}",
                rollback_errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        }
    }
}

impl std::error::Error for PatchError {}

impl From<ScanError> for PatchError {
    fn from(error: ScanError) -> Self {
        Self::Scan(error)
    }
}

impl From<MemoryError> for PatchError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DuniaBuild {
    Steam,
    Retail,
    Ubisoft,
    Unknown { file_size: Option<u64> },
}

impl DuniaBuild {
    fn from_file_size(file_size: Option<u64>) -> Self {
        match file_size {
            Some(STEAM_DUNIA_FILE_SIZE) => Self::Steam,
            Some(RETAIL_DUNIA_FILE_SIZE) => Self::Retail,
            Some(UBISOFT_DUNIA_FILE_SIZE) => Self::Ubisoft,
            file_size => Self::Unknown { file_size },
        }
    }
}

impl fmt::Display for DuniaBuild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Steam => write!(formatter, "Steam 1.03"),
            Self::Retail => write!(formatter, "Retail/GOG 1.03"),
            Self::Ubisoft => write!(formatter, "Ubisoft Connect 1.03"),
            Self::Unknown {
                file_size: Some(file_size),
            } => write!(formatter, "unknown build (file size {file_size})"),
            Self::Unknown { file_size: None } => {
                write!(formatter, "unknown build (file size unavailable)")
            }
        }
    }
}

fn detect_build(module: HMODULE) -> DuniaBuild {
    let file_size = module_path(module)
        .ok()
        .and_then(|path| std::fs::metadata(path).ok())
        .map(|metadata| metadata.len());

    DuniaBuild::from_file_size(file_size)
}

fn module_path(module: HMODULE) -> Result<PathBuf, String> {
    let mut capacity = 260;

    loop {
        let mut buffer = vec![0u16; capacity];
        let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) }
            as usize;
        if length == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }

        if capacity >= 32_768 {
            return Err("module path exceeds the Windows path limit".to_owned());
        }
        capacity = (capacity * 2).min(32_768);
    }
}

#[derive(Debug)]
struct PatchReport {
    configuration: Option<String>,
    build: Option<String>,
    image: Option<String>,
    outcomes: Vec<PatchOutcome>,
    warnings: Vec<String>,
}

impl PatchReport {
    fn new() -> Self {
        Self {
            configuration: None,
            build: None,
            image: None,
            outcomes: Vec::new(),
            warnings: Vec::new(),
        }
    }

    fn fail_enabled(&mut self, config: &PatchConfig, reason: String) {
        let settings = [
            ("jackal_tapes", config.jackal_tapes),
            ("devmode_always_on", config.devmode_always_on),
            ("predecessor_tapes", config.predecessor_tapes),
            ("machetes", config.machetes),
            ("no_blinking_items", config.no_blinking_items),
        ];

        self.outcomes = settings
            .into_iter()
            .map(|(name, enabled)| PatchOutcome {
                name,
                status: if enabled {
                    PatchStatus::Failed(reason.clone())
                } else {
                    PatchStatus::Disabled
                },
            })
            .collect();
    }
}

impl fmt::Display for PatchReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "fc2-systemdetection patch report")?;
        writeln!(
            formatter,
            "Configuration: {}",
            self.configuration.as_deref().unwrap_or("unavailable")
        )?;
        writeln!(
            formatter,
            "Dunia build: {}",
            self.build.as_deref().unwrap_or("unavailable")
        )?;
        writeln!(
            formatter,
            "Dunia image: {}",
            self.image.as_deref().unwrap_or("unavailable")
        )?;
        for outcome in &self.outcomes {
            writeln!(formatter, "{}: {}", outcome.name, outcome.status)?;
        }
        for warning in &self.warnings {
            writeln!(formatter, "configuration warning: {warning}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct PatchOutcome {
    name: &'static str,
    status: PatchStatus,
}

#[derive(Debug)]
enum PatchStatus {
    Disabled,
    Applied,
    AlreadyApplied,
    Failed(String),
}

impl fmt::Display for PatchStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(formatter, "disabled"),
            Self::Applied => write!(formatter, "applied"),
            Self::AlreadyApplied => write!(formatter, "already applied"),
            Self::Failed(reason) => write!(formatter, "FAILED: {reason}"),
        }
    }
}

fn emit_report(self_module: HMODULE, report: &str) {
    let mut wide: Vec<u16> = report.encode_utf16().collect();
    wide.push(0);
    unsafe {
        OutputDebugStringW(wide.as_ptr());
    }

    #[cfg(debug_assertions)]
    eprintln!("{report}");

    let log_path = module_path(self_module)
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from))
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|path| path.parent().map(PathBuf::from))
        })
        .map(|directory| directory.join("fc2-systemdetection.log"));

    if let Some(log_path) = log_path
        && let Err(error) = std::fs::write(&log_path, report)
    {
        let message = format!(
            "fc2-systemdetection: could not write {}: {error}\0",
            log_path.display()
        );
        let wide: Vec<u16> = message.encode_utf16().collect();
        unsafe {
            OutputDebugStringW(wide.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_dunia_file_sizes() {
        assert_eq!(
            DuniaBuild::from_file_size(Some(STEAM_DUNIA_FILE_SIZE)),
            DuniaBuild::Steam
        );
        assert_eq!(
            DuniaBuild::from_file_size(Some(RETAIL_DUNIA_FILE_SIZE)),
            DuniaBuild::Retail
        );
        assert_eq!(
            DuniaBuild::from_file_size(Some(UBISOFT_DUNIA_FILE_SIZE)),
            DuniaBuild::Ubisoft
        );
        assert_eq!(
            DuniaBuild::from_file_size(Some(123)),
            DuniaBuild::Unknown {
                file_size: Some(123)
            }
        );
        assert_eq!(
            DuniaBuild::from_file_size(None),
            DuniaBuild::Unknown { file_size: None }
        );
    }

    #[test]
    fn signature_target_accepts_original_and_patched_bytes() {
        for displacement in [0x0A, 0x14] {
            let memory = vec![0x80, 0x7E, 0x74, 0x00, 0x75, displacement, 0x3B, 0xCA, 0x75];
            let base = memory.as_ptr() as usize;
            let image = ModuleImage::for_test_section(base, 0, memory.clone(), ScanScope::Code);

            let target = find_signature_target(
                &image,
                signatures::JACKAL_TAPES,
                ScanScope::Code,
                5,
                &[0x0A],
                &[0x14],
            )
            .unwrap();

            assert_eq!(target, base + 5);
        }
    }

    #[test]
    fn signature_target_rejects_ambiguous_guarded_matches() {
        let occurrence = [0x80, 0x7E, 0x74, 0x00, 0x75, 0x0A, 0x3B, 0xCA, 0x75];
        let memory = occurrence
            .into_iter()
            .chain([0x90])
            .chain(occurrence)
            .collect::<Vec<_>>();
        let image = ModuleImage::for_test_section(
            memory.as_ptr() as usize,
            0,
            memory.clone(),
            ScanScope::Code,
        );

        let error = find_signature_target(
            &image,
            signatures::JACKAL_TAPES,
            ScanScope::Code,
            5,
            &[0x0A],
            &[0x14],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            PatchError::AmbiguousTarget { addresses, .. } if addresses.len() == 2
        ));
    }

    #[test]
    fn signature_target_rejects_unexpected_destination_bytes() {
        let memory = vec![0x80, 0x7E, 0x74, 0x00, 0x75, 0x24, 0x3B, 0xCA, 0x75];
        let image = ModuleImage::for_test_section(
            memory.as_ptr() as usize,
            0,
            memory.clone(),
            ScanScope::Code,
        );

        let error = find_signature_target(
            &image,
            signatures::JACKAL_TAPES,
            ScanScope::Code,
            5,
            &[0x0A],
            &[0x14],
        )
        .unwrap_err();

        assert!(matches!(
            error,
            PatchError::NoValidatedTarget { raw_matches: 1, .. }
        ));
    }

    #[test]
    fn retail_predecessor_uses_relocation_safe_rva_and_guard() {
        for bytes in [[0x8A, 0xC3], [0xB0, 0x01]] {
            let memory = Vec::from(bytes);
            let target = memory.as_ptr() as usize;
            let base = target - RETAIL_PREDECESSOR_RVA;
            let image = ModuleImage::for_test_section(
                base,
                RETAIL_PREDECESSOR_RVA,
                memory.clone(),
                ScanScope::Code,
            );

            let plan = plan_predecessor_tapes(&image, &DuniaBuild::Retail).unwrap();

            assert_eq!(plan.writes.len(), 1);
            assert_eq!(plan.writes[0].address, target);
        }
    }

    #[test]
    fn unknown_build_no_blinking_fallback_targets_the_save_disk_terminator() {
        let mut memory = b"Mesh_Highlight\0archBlink\0gadgets.ObjectiveIcons.SaveDisk\0".to_vec();
        let base = memory.as_mut_ptr() as usize;
        let image = ModuleImage::for_test_section(base, 0, memory.clone(), ScanScope::ReadOnlyData);
        let find = |needle: &[u8]| {
            memory
                .windows(needle.len())
                .position(|window| window == needle)
                .unwrap()
        };
        let targets = [
            find(b"Mesh_Highlight") + 4,
            find(b"archBlink") + 8,
            find(b"gadgets.ObjectiveIcons.SaveDisk") + 31,
        ];

        let plan =
            plan_no_blinking_items(&image, &DuniaBuild::Unknown { file_size: None }).unwrap();
        assert_eq!(
            plan.writes
                .iter()
                .map(|write| write.address - base)
                .collect::<Vec<_>>(),
            targets
        );
        assert_eq!(plan.apply().unwrap(), WriteState::Applied);
        assert!(targets.iter().all(|offset| memory[*offset] == b'.'));

        let second =
            plan_no_blinking_items(&image, &DuniaBuild::Unknown { file_size: None }).unwrap();
        assert_eq!(second.apply().unwrap(), WriteState::AlreadyApplied);
    }

    #[test]
    fn a_multi_write_plan_rolls_back_when_a_later_guard_changes() {
        let mut first = vec![0x0A];
        let mut second = vec![0x74];
        let plan = PatchPlan::new(vec![
            CheckedWrite::validated(first.as_mut_ptr() as usize, &[0x0A], &[0x14]).unwrap(),
            CheckedWrite::validated(second.as_mut_ptr() as usize, &[0x74], &[0xEB]).unwrap(),
        ])
        .unwrap();
        second[0] = 0x75;

        assert!(plan.apply().is_err());
        assert_eq!(first, [0x0A]);
        assert_eq!(second, [0x75]);
    }

    #[test]
    fn disabled_patches_do_not_resolve_or_scan() {
        let mut called = false;
        let prepared = prepare_patch("disabled", false, || {
            called = true;
            Err(PatchError::EmptyPlan)
        });

        assert!(!called);
        assert!(matches!(prepared, PreparedPatch::Disabled { .. }));
    }

    #[test]
    fn patch_status_is_unambiguous() {
        assert_eq!(PatchStatus::Disabled.to_string(), "disabled");
        assert_eq!(PatchStatus::Applied.to_string(), "applied");
        assert_eq!(PatchStatus::AlreadyApplied.to_string(), "already applied");
        assert_eq!(
            PatchStatus::Failed("bad bytes".to_owned()).to_string(),
            "FAILED: bad bytes"
        );
    }
}
