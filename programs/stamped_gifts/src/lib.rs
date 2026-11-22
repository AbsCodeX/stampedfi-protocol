//! StampedFi Gift-a-Stamp V2 — Isolated Per-Gift Solana Escrow Program (Pinocchio)
//! Issuer: STAMPED Labs, Inc. (stampedfi.com / stampedfi.io)
//!
//! Zero Bubble-Map Design:
//!   - Every gift gets its own deterministic 1-to-1 PDA seeded by `["sf-gift-v1", gift_id_16_bytes]`.
//!   - Clearing swaps land tokens directly `DEX Pool -> PDA ATA` via Jupiter `receiver = gift_pda`.
//!   - `ClaimGift` transfers exact locked tokens via `TransferChecked` (SPL Token & Token-2022) to the
//!     recipient's existing StampedFi wallet, closes the PDA ATA, and closes the PDA itself—returning
//!     100% of rent lamports to `sponsor` and leaving zero residual balance.
//!   - `ReleaseForCancel` releases the exact locked tokens inside an atomic cancel/swap-back transaction
//!     and closes both the PDA ATA and the PDA itself, returning 100% of rent to `sponsor`.

#![cfg_attr(not(test), no_std)]

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    entrypoint,
    instruction::{AccountMeta, Instruction, Seed, Signer},
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

pub const GIFT_SEED: &[u8] = b"sf-gift-v1";
pub const GIFT_DISCRIMINATOR: [u8; 8] = *b"SFGIFT01";

/// SPL Token Program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`)
pub const SPL_TOKEN_PROGRAM_ID: Pubkey = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93,
    0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91,
    0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];

/// SPL Token-2022 Program (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`)
pub const TOKEN_2022_PROGRAM_ID: Pubkey = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde,
    0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27,
    0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];

/// Compact `GiftEscrowV1` PDA layout (139 bytes):
///   [0..8]     discriminator ("SFGIFT01")
///   [8]        version (1)
///   [9]        status (1 = Active)
///   [10]       decimals (u8)
///   [11]       bump (u8)
///   [12..28]   gift_id ([u8; 16])
///   [28..60]   authority Pubkey (StampedFi gift settlement signer)
///   [60..92]   mint Pubkey
///   [92..124]  sponsor Pubkey (rent recovery destination)
///   [124..132] expected_amount (u64 LE)
///   [132..139] created_slot (u56 / stored via low 7 bytes, or 140 bytes full u64 -> use 140)
pub const GIFT_ESCROW_LEN: usize = 140;

pub const STATUS_ACTIVE: u8 = 1;

#[repr(u32)]
#[derive(Debug, PartialEq, Eq)]
pub enum GiftProgramError {
    InvalidInstruction = 7000,
    InvalidPda = 7001,
    Unauthorized = 7002,
    InvalidAccountData = 7003,
    AlreadyInitialized = 7004,
    NotActive = 7005,
    InvalidTokenProgram = 7006,
    InvalidSystemProgram = 7007,
    InvalidMint = 7008,
    InvalidSponsor = 7009,
    InvalidAmount = 7010,
}

impl From<GiftProgramError> for ProgramError {
    fn from(e: GiftProgramError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

#[cfg(not(test))]
entrypoint!(process_instruction);

#[cfg(all(not(test), any(target_os = "solana", target_arch = "bpf")))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (&tag, rest) = instruction_data
        .split_first()
        .ok_or(GiftProgramError::InvalidInstruction)?;

    match tag {
        0 => process_init_gift(program_id, accounts, rest),
        1 => process_settle_gift(program_id, accounts, rest), // ClaimGift
        2 => process_settle_gift(program_id, accounts, rest), // ReleaseForCancel (atomic swap-back)
        _ => Err(GiftProgramError::InvalidInstruction.into()),
    }
}

fn check_system_program(acc: &AccountInfo) -> ProgramResult {
    if acc.key() != &pinocchio_system::ID {
        return Err(GiftProgramError::InvalidSystemProgram.into());
    }
    Ok(())
}

fn check_token_program(acc: &AccountInfo) -> ProgramResult {
    let k = acc.key();
    if k != &SPL_TOKEN_PROGRAM_ID && k != &TOKEN_2022_PROGRAM_ID {
        return Err(GiftProgramError::InvalidTokenProgram.into());
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

/// Instruction 0: `InitGift`
/// Data (25 bytes): `[gift_id: 16][expected_amount: u64 LE][decimals: u8]`
/// Accounts:
///   0. `[signer, writable]` sponsor (pays PDA rent; receives rent back on claim/cancel)
///   1. `[signer]`           authority (StampedFi backend settlement signer)
///   2. `[writable]`         gift_pda (`["sf-gift-v1", gift_id]`)
///   3. `[]`                 mint
///   4. `[]`                 system_program
fn process_init_gift(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != 25 || accounts.len() < 5 {
        return Err(GiftProgramError::InvalidInstruction.into());
    }
    let sponsor = &accounts[0];
    let authority = &accounts[1];
    let gift_pda = &accounts[2];
    let mint = &accounts[3];
    let system_program = &accounts[4];

    if !sponsor.is_signer() || !authority.is_signer() {
        return Err(GiftProgramError::Unauthorized.into());
    }
    check_system_program(system_program)?;

    let mut gift_id = [0u8; 16];
    gift_id.copy_from_slice(&data[0..16]);
    let expected_amount = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let decimals = data[24];
    if expected_amount == 0 || decimals > 18 {
        return Err(GiftProgramError::InvalidAmount.into());
    }

    let (expected_pda, bump) = find_program_address(&[GIFT_SEED, &gift_id], program_id);
    if gift_pda.key() != &expected_pda {
        return Err(GiftProgramError::InvalidPda.into());
    }
    if gift_pda.data_len() > 0 {
        return Err(GiftProgramError::AlreadyInitialized.into());
    }

    let bump_slice = [bump];
    let seeds = [
        Seed::from(GIFT_SEED),
        Seed::from(gift_id.as_slice()),
        Seed::from(bump_slice.as_slice()),
    ];
    create_pda(sponsor, gift_pda, GIFT_ESCROW_LEN, program_id, &seeds)?;

    let slot = Clock::get()?.slot;
    let mut dst = gift_pda.try_borrow_mut_data()?;
    encode_escrow_state(
        &mut dst,
        &GiftEscrowData {
            version: 1,
            status: STATUS_ACTIVE,
            decimals,
            bump,
            gift_id,
            authority: *authority.key(),
            mint: *mint.key(),
            sponsor: *sponsor.key(),
            expected_amount,
            created_slot: slot,
        },
    )?;
    Ok(())
}

/// Instructions 1 (`ClaimGift`) & 2 (`ReleaseForCancel`)
/// Data (24 bytes): `[gift_id: 16][amount: u64 LE]`
/// Accounts:
///   0. `[signer, writable]` sponsor (receives 100% of ATA + PDA rent on close)
///   1. `[signer]`           authority (must match stored `authority`)
///   2. `[writable]`         gift_pda (`["sf-gift-v1", gift_id]`, closed at end of ix)
///   3. `[writable]`         vault_ata (owned by `gift_pda`, closed at end of ix)
///   4. `[writable]`         destination_ata (recipient ATA for claim, or clearing/temp ATA for cancel)
///   5. `[]`                 mint (must match stored `mint`)
///   6. `[]`                 token_program (SPL Token or Token-2022)
fn process_settle_gift(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() != 24 || accounts.len() < 7 {
        return Err(GiftProgramError::InvalidInstruction.into());
    }
    let sponsor = &accounts[0];
    let authority = &accounts[1];
    let gift_pda = &accounts[2];
    let vault_ata = &accounts[3];
    let destination_ata = &accounts[4];
    let mint = &accounts[5];
    let token_program = &accounts[6];

    if !sponsor.is_signer() || !authority.is_signer() {
        return Err(GiftProgramError::Unauthorized.into());
    }
    check_token_program(token_program)?;

    let mut gift_id = [0u8; 16];
    gift_id.copy_from_slice(&data[0..16]);
    let amount = u64::from_le_bytes(data[16..24].try_into().unwrap());
    if amount == 0 {
        return Err(GiftProgramError::InvalidAmount.into());
    }

    if unsafe { gift_pda.owner() } != program_id {
        return Err(GiftProgramError::InvalidPda.into());
    }

    let state = {
        let raw = gift_pda.try_borrow_data()?;
        decode_escrow_state(&raw)?
    };
    if state.status != STATUS_ACTIVE {
        return Err(GiftProgramError::NotActive.into());
    }
    if state.gift_id != gift_id {
        return Err(GiftProgramError::InvalidPda.into());
    }
    if &state.authority != authority.key() {
        return Err(GiftProgramError::Unauthorized.into());
    }
    if &state.mint != mint.key() {
        return Err(GiftProgramError::InvalidMint.into());
    }
    if &state.sponsor != sponsor.key() {
        return Err(GiftProgramError::InvalidSponsor.into());
    }

    let (expected_pda, bump) = find_program_address(&[GIFT_SEED, &gift_id], program_id);
    if gift_pda.key() != &expected_pda || bump != state.bump {
        return Err(GiftProgramError::InvalidPda.into());
    }

    let bump_slice = [bump];
    let seeds = [
        Seed::from(GIFT_SEED),
        Seed::from(gift_id.as_slice()),
        Seed::from(bump_slice.as_slice()),
    ];
    let signer = [Signer::from(&seeds)];

    // 1. CPI TransferChecked (SPL Token & Token-2022 tag = 12, u64 LE amount, u8 decimals)
    let mut transfer_data = [0u8; 10];
    transfer_data[0] = 12;
    transfer_data[1..9].copy_from_slice(&amount.to_le_bytes());
    transfer_data[9] = state.decimals;
    let transfer_metas = [
        AccountMeta::writable(vault_ata.key()),
        AccountMeta::readonly(mint.key()),
        AccountMeta::writable(destination_ata.key()),
        AccountMeta::readonly_signer(gift_pda.key()),
    ];
    let transfer_ix = Instruction {
        program_id: token_program.key(),
        accounts: &transfer_metas,
        data: &transfer_data,
    };
    invoke_signed(
        &transfer_ix,
        &[vault_ata, mint, destination_ata, gift_pda],
        &signer,
    )?;

    // 2. CPI CloseAccount (SPL Token & Token-2022 tag = 9) — returns 100% of ATA rent to sponsor.
    let close_data = [9u8; 1];
    let close_metas = [
        AccountMeta::writable(vault_ata.key()),
        AccountMeta::writable(sponsor.key()),
        AccountMeta::readonly_signer(gift_pda.key()),
    ];
    let close_ix = Instruction {
        program_id: token_program.key(),
        accounts: &close_metas,
        data: &close_data,
    };
    invoke_signed(&close_ix, &[vault_ata, sponsor, gift_pda], &signer)?;

    // 3. Zero & close GiftEscrowV1 PDA — returns 100% of PDA rent to sponsor.
    {
        let mut raw = gift_pda.try_borrow_mut_data()?;
        for byte in raw.iter_mut() {
            *byte = 0;
        }
    }
    let pda_lamports = gift_pda.lamports();
    unsafe {
        *gift_pda.borrow_mut_lamports_unchecked() = 0;
        *sponsor.borrow_mut_lamports_unchecked() = sponsor
            .lamports()
            .checked_add(pda_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GiftEscrowData {
    pub version: u8,
    pub status: u8,
    pub decimals: u8,
    pub bump: u8,
    pub gift_id: [u8; 16],
    pub authority: Pubkey,
    pub mint: Pubkey,
    pub sponsor: Pubkey,
    pub expected_amount: u64,
    pub created_slot: u64,
}

pub fn encode_escrow_state(dst: &mut [u8], s: &GiftEscrowData) -> Result<(), ProgramError> {
    if dst.len() < GIFT_ESCROW_LEN {
        return Err(GiftProgramError::InvalidAccountData.into());
    }
    dst[0..8].copy_from_slice(&GIFT_DISCRIMINATOR);
    dst[8] = s.version;
    dst[9] = s.status;
    dst[10] = s.decimals;
    dst[11] = s.bump;
    dst[12..28].copy_from_slice(&s.gift_id);
    dst[28..60].copy_from_slice(&s.authority);
    dst[60..92].copy_from_slice(&s.mint);
    dst[92..124].copy_from_slice(&s.sponsor);
    dst[124..132].copy_from_slice(&s.expected_amount.to_le_bytes());
    dst[132..140].copy_from_slice(&s.created_slot.to_le_bytes());
    Ok(())
}

pub fn decode_escrow_state(src: &[u8]) -> Result<GiftEscrowData, ProgramError> {
    if src.len() < GIFT_ESCROW_LEN || src[0..8] != GIFT_DISCRIMINATOR {
        return Err(GiftProgramError::InvalidAccountData.into());
    }
    let mut gift_id = [0u8; 16];
    gift_id.copy_from_slice(&src[12..28]);
    let mut authority = [0u8; 32];
    authority.copy_from_slice(&src[28..60]);
    let mut mint = [0u8; 32];
    mint.copy_from_slice(&src[60..92]);
    let mut sponsor = [0u8; 32];
    sponsor.copy_from_slice(&src[92..124]);
    let expected_amount = u64::from_le_bytes(src[124..132].try_into().unwrap());
    let created_slot = u64::from_le_bytes(src[132..140].try_into().unwrap());
    Ok(GiftEscrowData {
        version: src[8],
        status: src[9],
        decimals: src[10],
        bump: src[11],
        gift_id,
        authority,
        mint,
        sponsor,
        expected_amount,
        created_slot,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escrow_state_roundtrip_and_discriminator_guard() {
        let state = GiftEscrowData {
            version: 1,
            status: STATUS_ACTIVE,
            decimals: 5,
            bump: 254,
            gift_id: *b"g7Xk92mPqR4v0000",
            authority: [1u8; 32],
            mint: [2u8; 32],
            sponsor: [3u8; 32],
            expected_amount: 12_315_270_000_000,
            created_slot: 345_678_901,
        };
        let mut buf = [0u8; GIFT_ESCROW_LEN];
        encode_escrow_state(&mut buf, &state).expect("encode");
        let decoded = decode_escrow_state(&buf).expect("decode");
        assert_eq!(decoded, state);

        // Corrupt discriminator must be rejected
        buf[0] ^= 0xff;
        assert_eq!(
            decode_escrow_state(&buf).unwrap_err(),
            ProgramError::Custom(GiftProgramError::InvalidAccountData as u32)
        );
    }

    #[test]
    fn spl_and_token_2022_ids_are_distinct_32_byte_keys() {
        assert_ne!(SPL_TOKEN_PROGRAM_ID, TOKEN_2022_PROGRAM_ID);
        assert_eq!(GIFT_ESCROW_LEN, 140);
    }
}
