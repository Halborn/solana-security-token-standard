//! Corporate actions state structures

use bytemuck::{Pod, Zeroable};
use pinocchio::pubkey::Pubkey;

/// Rate for conversions and splits
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct Rate {
    /// Numerator
    pub numerator: u64,
    /// Denominator  
    pub denominator: u64,
    /// Rounding direction
    pub rounding: u8,
    /// Reserved
    pub _reserved: [u8; 7],
}

/// Receipt for corporate actions
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Pod, Zeroable)]
pub struct Receipt {
    /// Action ID
    pub action_id: u64,
    /// Account that received the action
    pub account: Pubkey,
    /// Amount processed
    pub amount: u64,
    /// Timestamp
    pub timestamp: i64,
    /// Reserved
    pub _reserved: [u8; 8],
}
