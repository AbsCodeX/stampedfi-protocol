//! StampedFi Proof-of-Conviction Protocol (STP-1) — Pinocchio Solana Program
//! Issuer: STAMPED Labs, Inc. (stampedfi.com / stampedfi.io)
//!
//! Designed for Solana Transaction v1 (SIMD-0296 / SIMD-0385, 4,096-byte atomic payloads):
//!   0 = InitializeRegistry: creates protocol config PDA with admin, authorized issuer, treasury, and B2B stamp fee
//!   1 = MintAtomicStamp:    creates immutable StampRecordV1 PDA storing packed 168-byte CardGenomeV1 + consensus Clock slot/ts
//!                           (designed to execute atomically in the same Tx v1 as a Jupiter/Pump/DFlow swap)
//!   2 = AnchorMerkleBatch:  anchors an hourly Merkle root of off-chain Ed25519 stamped-call-v1 digests permanently on L1
//!   3 = UpdateHolderStatus: authorized heartbeat oracle records cross-DEX holding / Stamp Shield 2x / dump transitions

#![no_std]

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

/// Deterministic placeholder Program ID for devnet/mainnet keypair deployment (replace via `solana-keygen`).
pub const ID: Pubkey = [
    0x53, 0x54, 0x41, 0x4d, 0x50, 0x45, 0x44, 0x46,
    0x49, 0x50, 0x52, 0x4f, 0x54, 0x4f, 0x43, 0x4f,
    0x4c, 0x56, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

pub const REGISTRY_SEED: &[u8] = b"stp1-registry";
pub const STAMP_SEED: &[u8] = b"stp1-stamp";
pub const BATCH_SEED: &[u8] = b"stp1-batch";

pub const REGISTRY_DISCRIMINATOR: [u8; 8] = *b"STP1REG1";
pub const STAMP_DISCRIMINATOR: [u8; 8] = *b"STP1STM1";
pub const BATCH_DISCRIMINATOR: [u8; 8] = *b"STP1MKL1";

/// Exact byte length of `CardGenomeV1` (byte-for-byte compatible with `@stampedfi/sas-verifier`).
pub const CARD_GENOME_V1_LEN: usize = 168;

/// Registry account layout (120 bytes):
///   [0..8]     discriminator ("STP1REG1")
///   [8..40]    admin Pubkey
///   [40..72]   authorized_issuer Pubkey (signs stamps, batches, and holder updates)
///   [72..104]  treasury Pubkey (collects B2B partner stamp fees)
///   [104..112] b2b_fee_lamports (u64 LE)
///   [112..119] total_stamps (u56 / stored as u64 at 112..120 -> 121 bytes with bump)
pub const REGISTRY_LEN: usize = 121;

/// Immutable StampRecordV1 PDA layout (276 bytes):
///   [0..8]     discriminator ("STP1STM1")
///   [8..176]   CardGenomeV1 (168 bytes — immutable after creation)
///   [176..184] recorded_slot (u64 LE from Clock::get())
///   [184..192] recorded_timestamp (i64 LE from Clock::get())
///   [192..224] caller_signer (Pubkey of wallet that co-signed atomic stamp, or zero if delegated)
///   [224..226] partner_id (u16 LE: 0 = StampedFi native, >0 = B2B integrating platform)
///   [226]      holder_status (u8: 1=Holding, 2=Shield2xTrimmed, 3=ExitedBeforeHorizon, 4=ClosedAfterHorizon)
///   [227]      bump (u8)
///   [228..236] holder_updated_slot (u64 LE)
///   [236..268] exit_tx_sig_prefix (32 bytes — SHA-256 of Solana exit signature when status flips)
///   [268..276] reserved ([u8; 8])
pub const STAMP_RECORD_LEN: usize = 276;

/// MerkleBatchV1 PDA layout (97 bytes):
///   [0..8]    discriminator ("STP1MKL1")
///   [8..16]   batch_id (u64 LE)
///   [16..48]  merkle_root ([u8; 32])
///   [48..52]  leaf_count (u32 LE)
///   [52..60]  anchored_slot (u64 LE)
///   [60..68]  anchored_timestamp (i64 LE)
///   [68..96]  reserved ([u8; 28])
///   [96]      bump (u8)
pub const MERKLE_BATCH_LEN: usize = 97;

#[repr(u32)]
pub enum StampedError {
    InvalidInstruction = 6000,
    InvalidPda = 6001,
    Unauthorized = 6002,
    InvalidGenome = 6003,
    InvalidHolderStatus = 6004,
    InvalidAccountData = 6005,
    InvalidTreasury = 6006,
    InvalidSystemProgram = 6007,
}

impl From<StampedError> for ProgramError {
    fn from(e: StampedError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if program_id != &ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (&tag, rest) = instruction_data
        .split_first()
        .ok_or(StampedError::InvalidInstruction)?;

    match tag {
        0 => process_initialize_registry(program_id, accounts, rest),
        1 => process_mint_atomic_stamp(program_id, accounts, rest),
        2 => process_anchor_merkle_batch(program_id, accounts, rest),
        3 => process_update_holder_status(program_id, accounts, rest),
        _ => Err(StampedError::InvalidInstruction.into()),
    }
}

fn check_system_program(acc: &AccountInfo) -> ProgramResult {
    if acc.key() != &pinocchio_system::ID {
        return Err(StampedError::InvalidSystemProgram.into());
    }
    Ok(())
}

fn create_pda(
    payer: &AccountInfo,
    target: &AccountInfo,
    space: usize,
    owner: &Pubkey,
    seeds: &[Seed],
) -> ProgramResult {
    let rent = Rent::get()?;
    let required_lamports = rent.minimum_balance(space);
    let signer = [Signer::from(seeds)];
    if target.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: target,
            lamports: required_lamports,
            space: space as u64,
            owner,
        }
        .invoke_signed(&signer)
    } else {
        let top_up = required_lamports.saturating_sub(target.lamports());
        if top_up > 0 {
            Transfer {
                from: payer,
                to: target,
                lamports: top_up,
            }
            .invoke()?;
        }
        Allocate {
            account: target,
            space: space as u64,
        }
        .invoke_signed(&signer)?;
        Assign {
            account: target,
            owner,
        }
        .invoke_signed(&signer)
    }
}

fn validate_registry(registry: &AccountInfo, program_id: &Pubkey) -> Result<([u8; 32], [u8; 32], u64), ProgramError> {
    if !registry.is_owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }
    let data = registry.try_borrow_data()?;
    if data.len() < REGISTRY_LEN || data[0..8] != REGISTRY_DISCRIMINATOR {
        return Err(StampedError::InvalidAccountData.into());
    }
    let mut issuer = [0u8; 32];
    issuer.copy_from_slice(&data[40..72]);
    let mut treasury = [0u8; 32];
    treasury.copy_from_slice(&data[72..104]);
    let fee = u64::from_le_bytes(data[104..112].try_into().map_err(|_| StampedError::InvalidAccountData)?);
    Ok((issuer, treasury, fee))
}

/// Instruction 0: InitializeRegistry
/// Accounts: [0] admin (signer, writable), [1] registry_pda (writable), [2] system_program
/// Data (72 bytes): authorized_issuer (32B) | treasury (32B) | b2b_fee_lamports (u64 LE)
fn process_initialize_registry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [admin, registry_pda, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !admin.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !registry_pda.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    check_system_program(system_program)?;
    if data.len() != 72 {
        return Err(StampedError::InvalidInstruction.into());
    }
    if !registry_pda.data_is_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let (expected_pda, bump) = find_program_address(&[REGISTRY_SEED], program_id);
    if registry_pda.key() != &expected_pda {
        return Err(StampedError::InvalidPda.into());
    }

    let bump_seed = [bump];
    let seeds = [Seed::from(REGISTRY_SEED), Seed::from(&bump_seed[..])];
    create_pda(admin, registry_pda, REGISTRY_LEN, program_id, &seeds)?;

    let mut buf = registry_pda.try_borrow_mut_data()?;
    buf[0..8].copy_from_slice(&REGISTRY_DISCRIMINATOR);
    buf[8..40].copy_from_slice(admin.key());
    buf[40..72].copy_from_slice(&data[0..32]);
    buf[72..104].copy_from_slice(&data[32..64]);
    buf[104..112].copy_from_slice(&data[64..72]);
    buf[112..120].copy_from_slice(&0u64.to_le_bytes());
    buf[120] = bump;
    Ok(())
}

/// Instruction 1: MintAtomicStamp (Solana Tx v1 atomic Swap-to-Stamp)
/// Accounts:
///   [0] payer (signer, writable)
///   [1] issuer (signer — must match registry.authorized_issuer)
///   [2] caller_wallet (signer — proves caller authored this stamp)
///   [3] registry_pda (writable)
///   [4] stamp_pda (writable — derived from [STAMP_SEED, stamp_id_8b])
///   [5] treasury (writable — receives b2b_fee_lamports when partner_id > 0)
///   [6] system_program
/// Data (170 bytes): partner_id (u16 LE) | CardGenomeV1 (168 bytes)
fn process_mint_atomic_stamp(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [payer, issuer, caller_wallet, registry_pda, stamp_pda, treasury, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() || !issuer.is_signer() || !caller_wallet.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !registry_pda.is_writable() || !stamp_pda.is_writable() || !treasury.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    check_system_program(system_program)?;
    if data.len() != 2 + CARD_GENOME_V1_LEN {
        return Err(StampedError::InvalidInstruction.into());
    }
    if !stamp_pda.data_is_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let (expected_reg, _) = find_program_address(&[REGISTRY_SEED], program_id);
    if registry_pda.key() != &expected_reg {
        return Err(StampedError::InvalidPda.into());
    }
    let (auth_issuer, reg_treasury, b2b_fee) = validate_registry(registry_pda, program_id)?;
    if issuer.key().as_ref() != auth_issuer.as_ref() {
        return Err(StampedError::Unauthorized.into());
    }
    if treasury.key().as_ref() != reg_treasury.as_ref() {
        return Err(StampedError::InvalidTreasury.into());
    }

    let partner_id = u16::from_le_bytes([data[0], data[1]]);
    let genome = &data[2..2 + CARD_GENOME_V1_LEN];
    // Validate CardGenomeV1 version (1), kind (0..=4), horizon (1 | 7 | 30), and ASCII Base62 stampId
    if genome[0] != 1 || genome[1] > 4 || (genome[3] != 1 && genome[3] != 7 && genome[3] != 30) {
        return Err(StampedError::InvalidGenome.into());
    }
    let stamp_id = &genome[4..12];
    for &b in stamp_id {
        if !b.is_ascii_alphanumeric() {
            return Err(StampedError::InvalidGenome.into());
        }
    }

    let (expected_stamp_pda, bump) = find_program_address(&[STAMP_SEED, stamp_id], program_id);
    if stamp_pda.key() != &expected_stamp_pda {
        return Err(StampedError::InvalidPda.into());
    }

    // Collect B2B protocol fee for external platforms (partner_id > 0); native consumer stamps stay free
    if partner_id > 0 && b2b_fee > 0 {
        Transfer {
            from: payer,
            to: treasury,
            lamports: b2b_fee,
        }
        .invoke()?;
    }

    let bump_seed = [bump];
    let seeds = [Seed::from(STAMP_SEED), Seed::from(stamp_id), Seed::from(&bump_seed[..])];
    create_pda(payer, stamp_pda, STAMP_RECORD_LEN, program_id, &seeds)?;

    let clock = Clock::get()?;
    {
        let mut sbuf = stamp_pda.try_borrow_mut_data()?;
        sbuf[0..8].copy_from_slice(&STAMP_DISCRIMINATOR);
        sbuf[8..176].copy_from_slice(genome);
        sbuf[176..184].copy_from_slice(&clock.slot.to_le_bytes());
        sbuf[184..192].copy_from_slice(&clock.unix_timestamp.to_le_bytes());
        sbuf[192..224].copy_from_slice(caller_wallet.key());
        sbuf[224..226].copy_from_slice(&partner_id.to_le_bytes());
        sbuf[226] = 1; // 1 = HOLDING_CONVICTION
        sbuf[227] = bump;
        sbuf[228..236].copy_from_slice(&clock.slot.to_le_bytes());
        sbuf[236..276].fill(0);
    }

    // Increment monotonic total_stamps counter on registry
    {
        let mut rbuf = registry_pda.try_borrow_mut_data()?;
        let current = u64::from_le_bytes(rbuf[112..120].try_into().map_err(|_| StampedError::InvalidAccountData)?);
        let next = current.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)?;
        rbuf[112..120].copy_from_slice(&next.to_le_bytes());
    }
    Ok(())
}

/// Instruction 2: AnchorMerkleBatch
/// Anchors a batch Merkle root of off-chain `stamped-call-v1` digests permanently on Solana L1.
/// Accounts: [0] payer (signer, writable), [1] issuer (signer), [2] registry_pda, [3] batch_pda (writable), [4] system_program
/// Data (44 bytes): batch_id (u64 LE) | merkle_root (32B) | leaf_count (u32 LE)
fn process_anchor_merkle_batch(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [payer, issuer, registry_pda, batch_pda, system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() || !issuer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !batch_pda.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    check_system_program(system_program)?;
    if data.len() != 44 {
        return Err(StampedError::InvalidInstruction.into());
    }
    if !batch_pda.data_is_empty() {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let (expected_reg, _) = find_program_address(&[REGISTRY_SEED], program_id);
    if registry_pda.key() != &expected_reg {
        return Err(StampedError::InvalidPda.into());
    }
    let (auth_issuer, _, _) = validate_registry(registry_pda, program_id)?;
    if issuer.key().as_ref() != auth_issuer.as_ref() {
        return Err(StampedError::Unauthorized.into());
    }

    let batch_id_bytes = &data[0..8];
    let (expected_batch_pda, bump) = find_program_address(&[BATCH_SEED, batch_id_bytes], program_id);
    if batch_pda.key() != &expected_batch_pda {
        return Err(StampedError::InvalidPda.into());
    }

    let bump_seed = [bump];
    let seeds = [Seed::from(BATCH_SEED), Seed::from(batch_id_bytes), Seed::from(&bump_seed[..])];
    create_pda(payer, batch_pda, MERKLE_BATCH_LEN, program_id, &seeds)?;

    let clock = Clock::get()?;
    let mut bbuf = batch_pda.try_borrow_mut_data()?;
    bbuf[0..8].copy_from_slice(&BATCH_DISCRIMINATOR);
    bbuf[8..16].copy_from_slice(batch_id_bytes);
    bbuf[16..48].copy_from_slice(&data[8..40]);
    bbuf[48..52].copy_from_slice(&data[40..44]);
    bbuf[52..60].copy_from_slice(&clock.slot.to_le_bytes());
    bbuf[60..68].copy_from_slice(&clock.unix_timestamp.to_le_bytes());
    bbuf[68..96].fill(0);
    bbuf[96] = bump;
    Ok(())
}

/// Instruction 3: UpdateHolderStatus (Cross-DEX Dump-Slashing / Stamp Shield Heartbeat)
/// Never mutates CardGenomeV1 ([8..176]); updates ONLY live holder_status + exit proof hash.
/// Accounts: [0] issuer (signer), [1] registry_pda, [2] stamp_pda (writable)
/// Data (33 bytes): new_status (u8: 1..=4) | exit_tx_sig_sha256 (32B)
fn process_update_holder_status(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let [issuer, registry_pda, stamp_pda] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !issuer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !stamp_pda.is_writable() || !stamp_pda.is_owned_by(program_id) {
        return Err(ProgramError::IllegalOwner);
    }
    if data.len() != 33 {
        return Err(StampedError::InvalidInstruction.into());
    }

    let (expected_reg, _) = find_program_address(&[REGISTRY_SEED], program_id);
    if registry_pda.key() != &expected_reg {
        return Err(StampedError::InvalidPda.into());
    }
    let (auth_issuer, _, _) = validate_registry(registry_pda, program_id)?;
    if issuer.key().as_ref() != auth_issuer.as_ref() {
        return Err(StampedError::Unauthorized.into());
    }

    let new_status = data[0];
    if new_status < 1 || new_status > 4 {
        return Err(StampedError::InvalidHolderStatus.into());
    }

    let clock = Clock::get()?;
    let mut sbuf = stamp_pda.try_borrow_mut_data()?;
    if sbuf.len() < STAMP_RECORD_LEN || sbuf[0..8] != STAMP_DISCRIMINATOR {
        return Err(StampedError::InvalidAccountData.into());
    }
    // Immutable CardGenomeV1 [8..176] is never touched; only heartbeat fields [226..268] update.
    sbuf[226] = new_status;
    sbuf[228..236].copy_from_slice(&clock.slot.to_le_bytes());
    sbuf[236..268].copy_from_slice(&data[1..33]);
    Ok(())
}
