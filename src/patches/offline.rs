//! Offline validation of patch recipes against an on-disk `Dunia.dll`.

use std::path::Path;

use super::memory::{WriteState, read_bytes};
use super::sigscan::{ModuleImage, Pattern, ScanScope};
use super::{
    DuniaBuild, PatchError, PatchPlan, RETAIL_NO_BLINK_RVAS, RETAIL_PREDECESSOR_RVA,
    STEAM_NO_BLINK_RVAS, plan_devmode_always_on, plan_jackal_tapes, plan_machetes,
    plan_no_blinking_items, plan_predecessor_tapes, signatures,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflinePatchState {
    AppliedToCopy,
    AlreadyPresent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPatch {
    pub name: &'static str,
    pub rvas: Vec<usize>,
    pub original_bytes: Vec<Vec<u8>>,
    pub replacement_bytes: Vec<Vec<u8>>,
    pub state: OfflinePatchState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuniaFileValidation {
    pub build: String,
    pub file_size: u64,
    pub image_size: usize,
    pub patches: Vec<ValidatedPatch>,
}

/// Validate every patch against an on-disk PE without loading or executing it.
///
/// Portex parses the file, its sections are reconstructed in ordinary heap
/// memory, and the real patch planners write only to that disposable copy.
pub fn validate_dunia_file(path: impl AsRef<Path>) -> Result<DuniaFileValidation, String> {
    let path = path.as_ref();
    let file = std::fs::read(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let build = DuniaBuild::from_file_size(Some(file.len() as u64));
    let mapped = ModuleImage::from_pe_file(&file)
        .map_err(|error| format!("could not map {}: {error}", path.display()))?;
    let image = &mapped.image;

    let mut failures = Vec::new();
    let mut prepared = Vec::new();
    for (name, result) in make_plans(image, &build) {
        match result {
            Ok(plan) => {
                let mut rvas = Vec::with_capacity(plan.writes.len());
                let mut original_bytes = Vec::with_capacity(plan.writes.len());
                let mut replacement_bytes = Vec::with_capacity(plan.writes.len());
                for write in &plan.writes {
                    rvas.push(write.address - image.base());
                    original_bytes.push(
                        read_bytes(write.address, write.expected.len())
                            .map_err(|error| format!("{name}: {error}"))?,
                    );
                    replacement_bytes.push(write.replacement.to_vec());
                }
                prepared.push((name, plan, rvas, original_bytes, replacement_bytes));
            }
            Err(error) => {
                let diagnostics = if name == "no_blinking_items" {
                    format!("; candidates: {}", no_blink_diagnostics(image))
                } else {
                    String::new()
                };
                failures.push(format!("{name}: {error}{diagnostics}"));
            }
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "static validation failed for {} ({build}):\n{}",
            path.display(),
            failures.join("\n")
        ));
    }

    validate_known_rvas(&build, &prepared)?;

    let mut patches = Vec::with_capacity(prepared.len());
    for (name, plan, rvas, original_bytes, replacement_bytes) in prepared {
        let state = match plan
            .apply()
            .map_err(|error| format!("{name} apply-to-copy failed: {error}"))?
        {
            WriteState::Applied => OfflinePatchState::AppliedToCopy,
            WriteState::AlreadyApplied => OfflinePatchState::AlreadyPresent,
        };
        patches.push(ValidatedPatch {
            name,
            rvas,
            original_bytes,
            replacement_bytes,
            state,
        });
    }

    for (name, result) in make_plans(image, &build) {
        let plan =
            result.map_err(|error| format!("{name} could not re-plan patched copy: {error}"))?;
        let state = plan
            .apply()
            .map_err(|error| format!("{name} reapply-to-copy failed: {error}"))?;
        if state != WriteState::AlreadyApplied {
            return Err(format!("{name} was not idempotent on the mapped copy"));
        }
    }

    Ok(DuniaFileValidation {
        build: build.to_string(),
        file_size: file.len() as u64,
        image_size: image.size(),
        patches,
    })
}

fn make_plans(
    image: &ModuleImage,
    build: &DuniaBuild,
) -> Vec<(&'static str, Result<PatchPlan, PatchError>)> {
    vec![
        ("jackal_tapes", plan_jackal_tapes(image)),
        ("devmode_always_on", plan_devmode_always_on(image)),
        ("predecessor_tapes", plan_predecessor_tapes(image, build)),
        ("machetes", plan_machetes(image)),
        ("no_blinking_items", plan_no_blinking_items(image, build)),
    ]
}

type PreparedPatch = (
    &'static str,
    PatchPlan,
    Vec<usize>,
    Vec<Vec<u8>>,
    Vec<Vec<u8>>,
);

fn validate_known_rvas(build: &DuniaBuild, prepared: &[PreparedPatch]) -> Result<(), String> {
    let (jackal, predecessor, machetes, no_blinking) = match build {
        DuniaBuild::Steam | DuniaBuild::Ubisoft => {
            (0x0074_E465, 0x002E_1D15, 0x0004_8939, STEAM_NO_BLINK_RVAS)
        }
        DuniaBuild::Retail => (
            0x0074_0F55,
            RETAIL_PREDECESSOR_RVA,
            0x0004_8A09,
            RETAIL_NO_BLINK_RVAS,
        ),
        DuniaBuild::Unknown { .. } => return Ok(()),
    };

    for (name, expected) in [
        ("jackal_tapes", vec![jackal]),
        ("predecessor_tapes", vec![predecessor]),
        ("machetes", vec![machetes]),
        ("no_blinking_items", no_blinking.to_vec()),
    ] {
        let actual = prepared
            .iter()
            .find_map(|(candidate, _, rvas, _, _)| (*candidate == name).then_some(rvas))
            .ok_or_else(|| format!("{name} did not produce a patch plan"))?;
        if actual != &expected {
            return Err(format!(
                "{name} resolved to {:?}, expected {:?} for {build}",
                format_rvas(actual),
                format_rvas(&expected)
            ));
        }
    }

    Ok(())
}

fn format_rvas(rvas: &[usize]) -> Vec<String> {
    rvas.iter().map(|rva| format!("0x{rva:08X}")).collect()
}

fn no_blink_diagnostics(image: &ModuleImage) -> String {
    [
        ("Mesh_Highlight", signatures::MESH_HIGHLIGHT, 4),
        ("archBlink", signatures::ARCH_BLINK, 8),
        ("SaveDisk", signatures::SAVE_DISK, 31),
    ]
    .into_iter()
    .map(|(name, signature, offset)| {
        let candidates = Pattern::parse(signature)
            .map(|pattern| image.scan(&pattern, ScanScope::ReadOnlyData))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|start| {
                let target = start.checked_add(offset)?;
                let byte = read_bytes(target, 1).ok()?;
                Some(format!(
                    "start RVA 0x{:08X} -> target RVA 0x{:08X} ({:02X})",
                    start - image.base(),
                    target - image.base(),
                    byte[0]
                ))
            })
            .collect::<Vec<_>>();
        format!("{name} [{}]", candidates.join(", "))
    })
    .collect::<Vec<_>>()
    .join("; ")
}
