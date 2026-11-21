import bs58 from 'bs58';
import {
  CARD_GENOME_V1_BYTES,
  decodeCardGenomeV1,
  type DecodedCardGenomeV1,
} from './index.js';

/**
 * Solana Transaction v1 (`SIMD-0296` / `SIMD-0385`) Instruction & Account Codecs
 * for `programs/stamped_protocol` (Pinocchio Solana Program — STP-1).
 *
 * Byte-for-byte compatible with `programs/stamped_protocol/src/lib.rs`.
 */

export const SOLANA_TX_V1_MAX_BYTES = 4096;
export const SOLANA_TX_V1_MAX_ACCOUNTS = 64;
export const SOLANA_TX_V1_FEATURE_GATE = 'txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL' as const;

export const STP1_REGISTRY_SEED = new TextEncoder().encode('stp1-registry');
export const STP1_STAMP_SEED = new TextEncoder().encode('stp1-stamp');
export const STP1_BATCH_SEED = new TextEncoder().encode('stp1-batch');

export const STP1_REGISTRY_DISCRIMINATOR = new TextEncoder().encode('STP1REG1');
export const STP1_STAMP_DISCRIMINATOR = new TextEncoder().encode('STP1STM1');
export const STP1_BATCH_DISCRIMINATOR = new TextEncoder().encode('STP1MKL1');

export const STP1_REGISTRY_LEN = 121;
export const STP1_STAMP_RECORD_LEN = 276;
export const STP1_MERKLE_BATCH_LEN = 97;

export const STP1_IX_TAG = {
  InitializeRegistry: 0,
  MintAtomicStamp: 1,
  AnchorMerkleBatch: 2,
  UpdateHolderStatus: 3,
} as const;

export const STP1_HOLDER_STATUS = {
  HoldingConviction: 1,
  Shield2xTrimmed: 2,
  ExitedBeforeHorizon: 3,
  ClosedAfterHorizon: 4,
} as const;

export type Stp1HolderStatusCode = (typeof STP1_HOLDER_STATUS)[keyof typeof STP1_HOLDER_STATUS];

export interface DecodedStampRecordV1 {
  genome: DecodedCardGenomeV1;
  recordedSlot: bigint;
  recordedTimestamp: bigint;
  callerSigner: string;
  partnerId: number;
  holderStatus: Stp1HolderStatusCode;
  bump: number;
  holderUpdatedSlot: bigint;
  exitTxSigSha256Hex: string | null;
}

export interface DecodedMerkleBatchV1 {
  batchId: bigint;
  merkleRootHex: string;
  leafCount: number;
  anchoredSlot: bigint;
  anchoredTimestamp: bigint;
  bump: number;
}

export interface TxV1AtomicBudgetEstimate {
  fits: boolean;
  estimatedBytes: number;
  headroomBytes: number;
  accountCount: number;
  computeUnitLimitValid: boolean;
  warnings: string[];
}

function decodePubkey32(b58: string, label: string): Uint8Array {
  const bytes = bs58.decode(b58);
  if (bytes.length !== 32) throw new Error(`invalid_${label}_pubkey`);
  return bytes;
}

function decodeHex32(hex: string, label: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/i.test(hex)) throw new Error(`invalid_${label}_hex32`);
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Instruction 0 (73 bytes): tag(1) | authorized_issuer(32) | treasury(32) | b2b_fee_lamports(u64 LE) */
export function encodeInitializeRegistryIxData(params: {
  authorizedIssuer: string;
  treasury: string;
  b2bFeeLamports: bigint;
}): Uint8Array {
  if (params.b2bFeeLamports < 0n) throw new Error('negative_b2b_fee');
  const out = new Uint8Array(73);
  const view = new DataView(out.buffer);
  out[0] = STP1_IX_TAG.InitializeRegistry;
  out.set(decodePubkey32(params.authorizedIssuer, 'issuer'), 1);
  out.set(decodePubkey32(params.treasury, 'treasury'), 33);
  view.setBigUint64(65, params.b2bFeeLamports, true);
  return out;
}

/** Instruction 1 (171 bytes): tag(1) | partner_id(u16 LE) | CardGenomeV1(168 bytes) */
export function encodeMintAtomicStampIxData(params: {
  partnerId: number;
  cardGenomeV1: Uint8Array;
}): Uint8Array {
  if (!Number.isInteger(params.partnerId) || params.partnerId < 0 || params.partnerId > 65_535) {
    throw new Error('invalid_partner_id');
  }
  if (params.cardGenomeV1.length !== CARD_GENOME_V1_BYTES) {
    throw new Error('invalid_card_genome_length');
  }
  const out = new Uint8Array(1 + 2 + CARD_GENOME_V1_BYTES);
  const view = new DataView(out.buffer);
  out[0] = STP1_IX_TAG.MintAtomicStamp;
  view.setUint16(1, params.partnerId, true);
  out.set(params.cardGenomeV1, 3);
  return out;
}

/** Instruction 2 (45 bytes): tag(1) | batch_id(u64 LE) | merkle_root(32) | leaf_count(u32 LE) */
export function encodeAnchorMerkleBatchIxData(params: {
  batchId: bigint;
  merkleRootHex: string;
  leafCount: number;
}): Uint8Array {
  if (params.batchId < 0n) throw new Error('invalid_batch_id');
  if (!Number.isInteger(params.leafCount) || params.leafCount < 1 || params.leafCount > 0xffff_ffff) {
    throw new Error('invalid_leaf_count');
  }
  const out = new Uint8Array(45);
  const view = new DataView(out.buffer);
  out[0] = STP1_IX_TAG.AnchorMerkleBatch;
  view.setBigUint64(1, params.batchId, true);
  out.set(decodeHex32(params.merkleRootHex, 'merkle_root'), 9);
  view.setUint32(41, params.leafCount, true);
  return out;
}

/** Instruction 3 (34 bytes): tag(1) | new_status(u8: 1..=4) | exit_tx_sig_sha256(32) */
export function encodeUpdateHolderStatusIxData(params: {
  newStatus: Stp1HolderStatusCode;
  exitTxSigSha256Hex: string | null;
}): Uint8Array {
  if (params.newStatus < 1 || params.newStatus > 4) throw new Error('invalid_holder_status');
  const out = new Uint8Array(34);
  out[0] = STP1_IX_TAG.UpdateHolderStatus;
  out[1] = params.newStatus;
  if (params.exitTxSigSha256Hex) {
    out.set(decodeHex32(params.exitTxSigSha256Hex, 'exit_tx_sig_sha256'), 2);
  }
  return out;
}

/** Decodes an on-chain 276-byte `StampRecordV1` PDA account straight from Solana RPC bytes. */
export function decodeStampRecordV1Account(bytes: Uint8Array): DecodedStampRecordV1 | null {
  if (!(bytes instanceof Uint8Array) || bytes.length < STP1_STAMP_RECORD_LEN) return null;
  if (!bytesEqual(bytes.subarray(0, 8), STP1_STAMP_DISCRIMINATOR)) return null;
  const genome = decodeCardGenomeV1(bytes.subarray(8, 176));
  if (!genome) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const recordedSlot = view.getBigUint64(176, true);
  const recordedTimestamp = view.getBigInt64(184, true);
  const callerSigner = bs58.encode(bytes.subarray(192, 224));
  const partnerId = view.getUint16(224, true);
  const statusRaw = bytes[226];
  if (statusRaw < 1 || statusRaw > 4) return null;
  const bump = bytes[227];
  const holderUpdatedSlot = view.getBigUint64(228, true);
  const exitSlice = bytes.subarray(236, 268);
  const exitTxSigSha256Hex = exitSlice.some((b) => b !== 0) ? Buffer.from(exitSlice).toString('hex') : null;
  return {
    genome,
    recordedSlot,
    recordedTimestamp,
    callerSigner,
    partnerId,
    holderStatus: statusRaw as Stp1HolderStatusCode,
    bump,
    holderUpdatedSlot,
    exitTxSigSha256Hex,
  };
}

/** Decodes an on-chain 97-byte `MerkleBatchV1` PDA account from Solana RPC bytes. */
export function decodeMerkleBatchV1Account(bytes: Uint8Array): DecodedMerkleBatchV1 | null {
  if (!(bytes instanceof Uint8Array) || bytes.length < STP1_MERKLE_BATCH_LEN) return null;
  if (!bytesEqual(bytes.subarray(0, 8), STP1_BATCH_DISCRIMINATOR)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    batchId: view.getBigUint64(8, true),
    merkleRootHex: Buffer.from(bytes.subarray(16, 48)).toString('hex'),
    leafCount: view.getUint32(48, true),
    anchoredSlot: view.getBigUint64(52, true),
    anchoredTimestamp: view.getBigInt64(60, true),
    bump: bytes[96],
  };
}

/**
 * Pre-flight byte & compute-budget validator for Solana Transaction v1 (`SIMD-0296`/`0385`)
 * atomic Swap + `MintAtomicStamp` bundles. Explicitly checks `computeUnitLimit > 0` because
 * Transaction v1 resolves an omitted `computeUnitLimit` to `0`!
 */
export function estimateTxV1AtomicBudget(input: {
  swapIxBytes: number;
  accountCount: number;
  signerCount?: number;
  includeZkProofBytes?: number;
  includeLightProofBytes?: number;
  computeUnitLimit?: number;
}): TxV1AtomicBudgetEstimate {
  const warnings: string[] = [];
  const signers = Math.max(1, input.signerCount ?? 2);
  const headerAndConfigBytes = 48; // 0x81 version + V1TransactionConfig + blockhash
  const accountKeysBytes = input.accountCount * 32;
  const stampIxBytes = 171 + (input.includeZkProofBytes ?? 0) + (input.includeLightProofBytes ?? 0) + 12;
  const swapBytes = Math.max(0, input.swapIxBytes) + 12;
  const trailingSigBytes = signers * 64;
  const estimatedBytes = headerAndConfigBytes + accountKeysBytes + swapBytes + stampIxBytes + trailingSigBytes;
  const headroomBytes = SOLANA_TX_V1_MAX_BYTES - estimatedBytes;
  const computeUnitLimitValid = typeof input.computeUnitLimit === 'number' && input.computeUnitLimit >= 50_000;

  if (!computeUnitLimitValid) {
    warnings.push('Solana Transaction v1 defaults omitted computeUnitLimit to 0 — set explicit computeUnitLimit >= 50,000.');
  }
  if (input.accountCount > SOLANA_TX_V1_MAX_ACCOUNTS) {
    warnings.push(`Account count (${input.accountCount}) exceeds Transaction v1 inline limit (${SOLANA_TX_V1_MAX_ACCOUNTS}).`);
  }
  if (estimatedBytes > SOLANA_TX_V1_MAX_BYTES) {
    warnings.push(`Estimated v1 transaction size (${estimatedBytes} B) exceeds 4,096-byte ceiling.`);
  }

  return {
    fits: estimatedBytes <= SOLANA_TX_V1_MAX_BYTES && input.accountCount <= SOLANA_TX_V1_MAX_ACCOUNTS && computeUnitLimitValid,
    estimatedBytes,
    headroomBytes,
    accountCount: input.accountCount,
    computeUnitLimitValid,
    warnings,
  };
}
