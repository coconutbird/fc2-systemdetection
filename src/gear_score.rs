//! GearScore - System scoring class
//!
//! Structure layout (20 bytes):
//!   0x00: vtable
//!   0x04: scores[0] (f32) - CPU score
//!   0x08: scores[1] (f32) - GPU score
//!   0x0C: confidence[0] (f32) - CPU confidence
//!   0x10: confidence[1] (f32) - GPU confidence
//!
//! VTable: [destructor, GetScore, ComputeScore]

use std::ffi::c_void;

/// Sentinel value for uncomputed scores (-FLT_MAX)
const SCORE_UNCOMPUTED: f32 = -3.4028235e38;

/// GearScore class (20 bytes)
#[repr(C)]
pub struct GearScore {
    vtable: *const GearScoreVTable, // offset 0x00
    scores: [f32; 2],               // offset 0x04 (CPU, GPU)
    confidence: [f32; 2],           // offset 0x0C (CPU, GPU confidence)
}

unsafe impl Send for GearScore {}
unsafe impl Sync for GearScore {}

#[repr(C)]
struct GearScoreVTable {
    destructor: unsafe extern "thiscall" fn(*mut GearScore, u8) -> *mut c_void,
    get_score: unsafe extern "thiscall" fn(*mut GearScore, i32, i32, *mut f32) -> f32,
    compute_score: unsafe extern "thiscall" fn(*mut GearScore, i32, i32) -> i32,
}

static GEAR_SCORE_VTABLE: GearScoreVTable = GearScoreVTable {
    destructor: gear_score_destructor,
    get_score: gear_score_get_score,
    compute_score: gear_score_compute_score,
};

unsafe extern "thiscall" fn gear_score_destructor(this: *mut GearScore, flags: u8) -> *mut c_void {
    if flags & 1 != 0 {
        let _ = Box::from_raw(this);
    }
    this as *mut c_void
}

/// GetScore - returns score for given type, computing if needed
unsafe extern "thiscall" fn gear_score_get_score(
    this: *mut GearScore,
    score_type: i32,
    param: i32,
    confidence_out: *mut f32,
) -> f32 {
    if !(0..2).contains(&score_type) {
        return 0.0;
    }

    let idx = score_type as usize;

    // Compute score if not yet computed (check for -FLT_MAX sentinel)
    if (*this).scores[idx] == SCORE_UNCOMPUTED {
        // Call vtable[2] (ComputeScore) like FC3 does
        gear_score_compute_score(this, score_type, param);
    }

    if !confidence_out.is_null() {
        *confidence_out = (*this).confidence[idx];
    }

    (*this).scores[idx]
}

/// ComputeScore - computes and stores score for given type
unsafe extern "thiscall" fn gear_score_compute_score(
    this: *mut GearScore,
    score_type: i32,
    _param: i32,
) -> i32 {
    if !(0..2).contains(&score_type) {
        return score_type;
    }

    let idx = score_type as usize;

    // Return good default scores (0.8 = 80%)
    (*this).scores[idx] = 0.8;
    (*this).confidence[idx] = 1.0;

    score_type
}

impl Default for GearScore {
    fn default() -> Self {
        Self::new()
    }
}

impl GearScore {
    pub fn new() -> Self {
        println!("systemdetection: Initializing GearScore");
        GearScore {
            vtable: &GEAR_SCORE_VTABLE,
            scores: [SCORE_UNCOMPUTED; 2],
            confidence: [1.0; 2],
        }
    }
}
