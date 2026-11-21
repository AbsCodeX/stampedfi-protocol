import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import {
  SIGNATURE_SCHEME,
  SOLANA_ATTESTATION_SERVICE_PROGRAM_ID,
  type VerifyOptions,
} from './index.js';

/**
 * Canonical StampedFi Caller Reputation Engine (`StampScore` 0–1000) &
 * Official Solana Attestation Service (`SAS`) Tokenized Caller Passport (`STAMPED_CALLER_PASSPORT_V1`).
 *
 * Compatible with SAS Mainnet/Devnet (`22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG`) and
 * Solana Mobile Seeker's `StampProtocolMath.kt`.
 */

export const CALLER_PASSPORT_SCHEMA = 'stamped-passport-v1' as const;
export const SAS_CALLER_PASSPORT_BINARY_BYTES = 20;

export type StampScoreTier =
  | 'Unranked'
  | 'Bronze'
  | 'Silver'
  | 'Gold'
  | 'Platinum'
  | 'Diamond Sovereign';

export type HumanVerificationTier = 0 | 1 | 2 | 3; // 0=Unverified, 1=X/Social, 2=Passkey, 3=SeekerSGT

export interface StampScoreInput {
  verifiedCalls: number;
  /** Fraction of audited calls reaching >= 2.0x (0..1) */
  hitRate2x: number;
  /** Fraction of calls held through horizon or Stamp Shield 2x trim without early dump (0..1) */
  holdDiscipline: number;
  /** Number of early cross-DEX dumps before declared horizon */
  earlyDumpCount: number;
  /** Median peak/review multiple across audited calls (e.g. 1.85 = 1.85x) */
  medianMultiple: number;
  /** Total verified volume driven through caller's Stamped cards in USD */
  totalVolumeDrivenUsd: number;
  /** Hardware-human / social identity level */
  humanTier: HumanVerificationTier;
}

export interface StampScoreBreakdown {
  score: number; // 0..1000
  tier: StampScoreTier;
  callerFeeShareBps: number; // 2000..3500 (20%..35% of protocol fee)
  hitRate2xBps: number; // 0..10000
  holdDisciplineBps: number; // 0..10000
  medianMultipleBps: number; // 10000 = 1.00x
}

export interface CallerPassportPayload {
  schema: typeof CALLER_PASSPORT_SCHEMA;
  handle: string;
  walletCommitmentHex: string;
  sasProgramId: typeof SOLANA_ATTESTATION_SERVICE_PROGRAM_ID;
  stampScore: number;
  tier: StampScoreTier;
  callerFeeShareBps: number;
  totalAuditedCalls: number;
  hitRate2xBps: number;
  holdDisciplineBps: number;
  medianMultipleBps: number;
  humanTier: HumanVerificationTier;
  lastAuditedEpoch: number;
  sasLayoutHex: string;
  issuedAt: string;
  expiresAt: string;
  digestHex: string;
}

export interface SignedCallerPassport extends CallerPassportPayload {
  kid: string;
  issuerPubkey: string;
  signatureBase58: string;
  signatureScheme: typeof SIGNATURE_SCHEME;
}

const HEX64_REGEX = /^[0-9a-f]{64}$/;
const SEED_HEX_REGEX = /^[0-9a-fA-F]{64}$/;
const DEFAULT_CLOCK_SKEW_MS = 30_000;

function clamp(v: number, lo: number, hi: number): number {
  if (!Number.isFinite(v)) return lo;
  return Math.max(lo, Math.min(hi, v));
}

/**
 * Deterministic `StampScore` (0–1000) weighted across:
 * - Audited 2x Hit Rate (350 pts)
 * - Cross-DEX Hold Discipline (300 pts)
 * - Track-Record Depth & Median Multiple (200 pts)
 * - Verified Copy-Trade Volume & Hardware-Human Proof (150 pts)
 * - Early Dump-Slashing Penalty (-45 pts per early dump, capped)
 */
export function computeStampScore(input: StampScoreInput): StampScoreBreakdown {
  const calls = Math.max(0, Math.floor(input.verifiedCalls));
  const hit = clamp(input.hitRate2x, 0, 1);
  const disc = clamp(input.holdDiscipline, 0, 1);
  const dumps = Math.max(0, Math.floor(input.earlyDumpCount));
  const med = clamp(input.medianMultiple, 0, 100);
  const vol = Math.max(0, Number.isFinite(input.totalVolumeDrivenUsd) ? input.totalVolumeDrivenUsd : 0);

  const hitRate2xBps = Math.round(hit * 10_000);
  const holdDisciplineBps = Math.round(disc * 10_000);
  const medianMultipleBps = Math.round(med * 10_000);

  if (calls === 0) {
    return {
      score: 0,
      tier: 'Unranked',
      callerFeeShareBps: 2500,
      hitRate2xBps: 0,
      holdDisciplineBps: 0,
      medianMultipleBps: 0,
    };
  }

  // Smooth sample-size confidence factor so 1 lucky call cannot score 1000
  const confidence = Math.min(1, calls / 10);
  const hitPts = hit * 350 * confidence;
  const discPts = disc * 300 * confidence;
  const depthPts = Math.min(100, Math.log10(calls + 1) * 60) + Math.min(100, Math.max(0, (med - 1) * 50) * confidence);
  const volPts = Math.min(90, Math.log10(vol + 10) * 15);
  const humanPts = input.humanTier === 3 ? 60 : input.humanTier === 2 ? 45 : input.humanTier === 1 ? 25 : 0;
  const dumpPenalty = Math.min(350, dumps * 45);

  const score = Math.round(clamp(hitPts + discPts + depthPts + volPts + humanPts - dumpPenalty, 0, 1000));

  let tier: StampScoreTier;
  let callerFeeShareBps: number;
  if (score >= 880 && calls >= 25 && dumps === 0) {
    tier = 'Diamond Sovereign';
    callerFeeShareBps = 3500;
  } else if (score >= 760) {
    tier = 'Platinum';
    callerFeeShareBps = 3000;
  } else if (score >= 620) {
    tier = 'Gold';
    callerFeeShareBps = 2750;
  } else if (score >= 450) {
    tier = 'Silver';
    callerFeeShareBps = 2500;
  } else {
    tier = 'Bronze';
    callerFeeShareBps = 2500;
  }

  return {
    score,
    tier,
    callerFeeShareBps,
    hitRate2xBps,
    holdDisciplineBps,
    medianMultipleBps,
  };
}

/**
 * Encodes the 20-byte packed `STAMPED_CALLER_PASSPORT_V1` attestation data payload
 * for direct registration & read-only on-chain verification via Solana Attestation Service (SAS):
 *   [0..2]   stamp_score (u16 LE, 0..1000)
 *   [2..6]   total_audited_calls (u32 LE)
 *   [6..8]   hit_rate_2x_bps (u16 LE, 0..10000)
 *   [8..10]  hold_discipline_bps (u16 LE, 0..10000)
 *   [10..14] median_multiple_bps (u32 LE, 10000 = 1.00x)
 *   [14]     human_tier (u8: 0..3)
 *   [15]     reserved (u8 = 0)
 *   [16..20] last_audited_epoch (u32 LE)
 */
export function encodeSasCallerPassportV1(fields: {
  stampScore: number;
  totalAuditedCalls: number;
  hitRate2xBps: number;
  holdDisciplineBps: number;
  medianMultipleBps: number;
  humanTier: HumanVerificationTier;
  lastAuditedEpoch: number;
}): Uint8Array {
  const out = new Uint8Array(SAS_CALLER_PASSPORT_BINARY_BYTES);
  const view = new DataView(out.buffer);
  view.setUint16(0, Math.round(clamp(fields.stampScore, 0, 1000)), true);
  view.setUint32(2, Math.max(0, Math.floor(fields.totalAuditedCalls)), true);
  view.setUint16(6, Math.round(clamp(fields.hitRate2xBps, 0, 10_000)), true);
  view.setUint16(8, Math.round(clamp(fields.holdDisciplineBps, 0, 10_000)), true);
  view.setUint32(10, Math.max(0, Math.floor(fields.medianMultipleBps)), true);
  out[14] = fields.humanTier;
  out[15] = 0;
  view.setUint32(16, Math.max(0, Math.floor(fields.lastAuditedEpoch)), true);
  return out;
}

export function decodeSasCallerPassportV1(bytes: Uint8Array) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== SAS_CALLER_PASSPORT_BINARY_BYTES) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const stampScore = view.getUint16(0, true);
  const hitRate2xBps = view.getUint16(6, true);
  const holdDisciplineBps = view.getUint16(8, true);
  const humanTier = bytes[14];
  if (stampScore > 1000 || hitRate2xBps > 10_000 || holdDisciplineBps > 10_000 || humanTier > 3) return null;
  return {
    stampScore,
    totalAuditedCalls: view.getUint32(2, true),
    hitRate2xBps,
    holdDisciplineBps,
    medianMultipleBps: view.getUint32(10, true),
    humanTier: humanTier as HumanVerificationTier,
    lastAuditedEpoch: view.getUint32(16, true),
  };
}

export function callerPassportDigest(core: Omit<CallerPassportPayload, 'digestHex'>): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        schema: CALLER_PASSPORT_SCHEMA,
        handle: core.handle,
        walletCommitmentHex: core.walletCommitmentHex,
        sasProgramId: SOLANA_ATTESTATION_SERVICE_PROGRAM_ID,
        stampScore: core.stampScore,
        tier: core.tier,
        callerFeeShareBps: core.callerFeeShareBps,
        totalAuditedCalls: core.totalAuditedCalls,
        hitRate2xBps: core.hitRate2xBps,
        holdDisciplineBps: core.holdDisciplineBps,
        medianMultipleBps: core.medianMultipleBps,
        humanTier: core.humanTier,
        lastAuditedEpoch: core.lastAuditedEpoch,
        sasLayoutHex: core.sasLayoutHex,
        issuedAt: core.issuedAt,
        expiresAt: core.expiresAt,
      }),
      'utf8'
    )
    .digest('hex');
}

export function signCallerPassport(
  input: Omit<CallerPassportPayload, 'schema' | 'sasProgramId' | 'sasLayoutHex' | 'digestHex'>,
  secretSeedHex: string,
  kid = 'sf-ed25519-2026-q4'
): SignedCallerPassport {
  if (!SEED_HEX_REGEX.test(secretSeedHex)) throw new Error('bad_secret_seed');
  if (!HEX64_REGEX.test(input.walletCommitmentHex)) throw new Error('bad_wallet_commitment');
  const sasLayoutHex = Buffer.from(encodeSasCallerPassportV1(input)).toString('hex');
  const core: Omit<CallerPassportPayload, 'digestHex'> = {
    schema: CALLER_PASSPORT_SCHEMA,
    handle: input.handle,
    walletCommitmentHex: input.walletCommitmentHex,
    sasProgramId: SOLANA_ATTESTATION_SERVICE_PROGRAM_ID,
    stampScore: input.stampScore,
    tier: input.tier,
    callerFeeShareBps: input.callerFeeShareBps,
    totalAuditedCalls: input.totalAuditedCalls,
    hitRate2xBps: input.hitRate2xBps,
    holdDisciplineBps: input.holdDisciplineBps,
    medianMultipleBps: input.medianMultipleBps,
    humanTier: input.humanTier,
    lastAuditedEpoch: input.lastAuditedEpoch,
    sasLayoutHex,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
  };
  const digestHex = callerPassportDigest(core);
  const full: CallerPassportPayload = { ...core, digestHex };
  const seed = Uint8Array.from(Buffer.from(secretSeedHex, 'hex'));
  const kp = nacl.sign.keyPair.fromSeed(seed);
  try {
    const msg = new TextEncoder().encode(JSON.stringify({ scheme: SIGNATURE_SCHEME, kid, ...full }));
    const sig = nacl.sign.detached(msg, kp.secretKey);
    return {
      ...full,
      kid,
      issuerPubkey: bs58.encode(kp.publicKey),
      signatureBase58: bs58.encode(sig),
      signatureScheme: SIGNATURE_SCHEME,
    };
  } finally {
    kp.secretKey.fill(0);
    seed.fill(0);
  }
}

export function verifySignedCallerPassport(
  signed: SignedCallerPassport,
  expectedIssuerOrOpts?: string | VerifyOptions
): boolean {
  try {
    const opts: VerifyOptions = typeof expectedIssuerOrOpts === 'string'
      ? { expectedIssuerPubkey: expectedIssuerOrOpts }
      : expectedIssuerOrOpts ?? {};
    const skew = opts.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
    if (!signed || signed.schema !== CALLER_PASSPORT_SCHEMA || signed.signatureScheme !== SIGNATURE_SCHEME) return false;
    if (signed.sasProgramId !== SOLANA_ATTESTATION_SERVICE_PROGRAM_ID) return false;
    if (!HEX64_REGEX.test(signed.walletCommitmentHex) || !HEX64_REGEX.test(signed.digestHex)) return false;
    const expectedSasHex = Buffer.from(encodeSasCallerPassportV1(signed)).toString('hex');
    if (signed.sasLayoutHex !== expectedSasHex) return false;
    if (signed.digestHex !== callerPassportDigest(signed)) return false;
    const expMs = Date.parse(signed.expiresAt);
    const nowMs = opts.nowMs ?? Date.now();
    if (Number.isNaN(expMs) || nowMs > expMs + skew) return false;
    const pub = bs58.decode(signed.issuerPubkey);
    const sig = bs58.decode(signed.signatureBase58);
    if (pub.length !== 32 || sig.length !== 64) return false;
    if (opts.expectedIssuerPubkey && signed.issuerPubkey !== opts.expectedIssuerPubkey) return false;
    const msg = new TextEncoder().encode(
      JSON.stringify({
        scheme: SIGNATURE_SCHEME,
        kid: signed.kid,
        schema: signed.schema,
        handle: signed.handle,
        walletCommitmentHex: signed.walletCommitmentHex,
        sasProgramId: signed.sasProgramId,
        stampScore: signed.stampScore,
        tier: signed.tier,
        callerFeeShareBps: signed.callerFeeShareBps,
        totalAuditedCalls: signed.totalAuditedCalls,
        hitRate2xBps: signed.hitRate2xBps,
        holdDisciplineBps: signed.holdDisciplineBps,
        medianMultipleBps: signed.medianMultipleBps,
        humanTier: signed.humanTier,
        lastAuditedEpoch: signed.lastAuditedEpoch,
        sasLayoutHex: signed.sasLayoutHex,
        issuedAt: signed.issuedAt,
        expiresAt: signed.expiresAt,
        digestHex: signed.digestHex,
      })
    );
    return nacl.sign.detached.verify(msg, sig, pub);
  } catch {
    return false;
  }
}
