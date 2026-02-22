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

use cppvtable::proc::{cppvtable, cppvtable_impl};
use std::ffi::c_void;

/// Sentinel value for uncomputed scores (-FLT_MAX)
const SCORE_UNCOMPUTED: f32 = -3.4028235e38;

/// IGearScore interface definition
#[cppvtable]
pub trait IGearScore {
    fn destructor(&mut self, flags: u8) -> *mut c_void;
    fn get_score(&mut self, score_type: i32, param: i32, confidence_out: *mut f32) -> f32;
    fn compute_score(&mut self, score_type: i32, param: i32) -> i32;
}

/// GearScore class (20 bytes)
#[repr(C)]
pub struct GearScore {
    pub vtable_i_gear_score: *const IGearScoreVTable, // offset 0x00
    scores: [f32; 2],                                 // offset 0x04 (CPU, GPU)
    confidence: [f32; 2],                             // offset 0x0C (CPU, GPU confidence)
}

unsafe impl Send for GearScore {}
unsafe impl Sync for GearScore {}

#[cppvtable_impl(IGearScore)]
impl GearScore {
    fn destructor(&mut self, flags: u8) -> *mut c_void {
        if flags & 1 != 0 {
            unsafe {
                let _ = Box::from_raw(self as *mut Self);
            }
        }
        self as *mut Self as *mut c_void
    }

    /// GetScore - returns score for given type, computing if needed
    fn get_score(&mut self, score_type: i32, param: i32, confidence_out: *mut f32) -> f32 {
        if !(0..2).contains(&score_type) {
            return 0.0;
        }

        let idx = score_type as usize;

        // Compute score if not yet computed (check for -FLT_MAX sentinel)
        if self.scores[idx] == SCORE_UNCOMPUTED {
            self.compute_score(score_type, param);
        }

        if !confidence_out.is_null() {
            unsafe {
                *confidence_out = self.confidence[idx];
            }
        }

        self.scores[idx]
    }

    /// ComputeScore - computes and stores score for given type
    fn compute_score(&mut self, score_type: i32, _param: i32) -> i32 {
        if !(0..2).contains(&score_type) {
            return score_type;
        }

        let idx = score_type as usize;

        // Return good default scores (0.8 = 80%)
        self.scores[idx] = 0.8;
        self.confidence[idx] = 1.0;

        score_type
    }
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
            vtable_i_gear_score: Self::VTABLE_I_GEAR_SCORE,
            scores: [SCORE_UNCOMPUTED; 2],
            confidence: [1.0; 2],
        }
    }
}
