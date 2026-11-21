/**
 * @stampedfi/sas-verifier — Official MIT Open-Source Cryptographic Verifier SDK by STAMPED Labs, Inc.
 *
 * Verifies in <1ms offline (zero RPC calls, zero proprietary backend secrets):
 * 1. `stamped-call-v1` Stamped Conviction Call & Card Proofs + Deterministic Binary Card Genome (Solana Tx v1)
 * 2. `stamped-sas-v1` Solana token safety attestations (with TTL expiry enforcement)
 * 3. `stamped-tier-v1` Zero-Dox holder tier receipts (Shrimp / Dolphin / Shark / Whale)
 * 4. `stamped-sgt-v1` Solana Mobile Seeker Genesis Token Hardware-Human badges
 * 5. `guardSolanaBlinkUrl` Solana Actions / Blink URL pre-execution safety gate
 */
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export const SAS_SCHEMA = 'stamped-sas-v1' as const;
export const TIER_SCHEMA = 'stamped-tier-v1' as const;
export const SGT_SCHEMA = 'stamped-sgt-v1' as const;
export const CALL_STAMP_SCHEMA = 'stamped-call-v1' as const;
export const SIGNATURE_SCHEME = 'ed25519-v1' as const;
export const CARD_GENOME_VERSION = 1 as const;
export const SEEKER_SGT_GROUP_ADDRESS = 'GT22s89nU4iWFkNXj1Bw6uYhJJWDRPpShHt4Bk8f99Te' as const;
export const SOLANA_ATTESTATION_SERVICE_PROGRAM_ID = '22zoJMtdu4tQc2PzL74ZUT7FrwgB1Udec8DdW4yw4BdG' as const;

export type SafetyLevel = 'ok' | 'caution' | 'risky' | 'blocked' | 'unknown';
export type SasSchema = typeof SAS_SCHEMA;
export type HolderTier = 'Shrimp' | 'Dolphin' | 'Shark' | 'Whale';
export type StampKind = 'buy_call' | 'position' | 'closed_pnl' | 'spotlight' | 'gift';

export interface VerifyOptions {
  /** Expected Base58 Ed25519 public key of the StampedFi issuer. */
  expectedIssuerPubkey?: string;
  /** Override current wall-clock time in ms (useful for deterministic tests). Defaults to Date.now(). */
  nowMs?: number;
  /** Allowed clock skew in ms when checking issuedAt / expiresAt. Defaults to 30_000 (30s). */
  clockSkewMs?: number;
  /** Reject attestations older than this many ms when `expiresAt` is absent. */
  maxAgeMs?: number;
  /** Reject unsigned payloads even if SHA-256 digest matches. Defaults to true. */
  requireSignature?: boolean;
}

export interface SafetyAttestation {
  schema: SasSchema;
  mint: string;
  level: SafetyLevel;
  tradeAllowed: boolean;
  quickBuyAllowed: boolean;
  coverageBps: number;
  flagIds: string[];
  dangerCount: number;
  warnCount: number;
  summary: string;
  attestedAt: string;
  /** Optional ISO expiry timestamp; enforced automatically when present. */
  expiresAt?: string;
  digestHex: string;
}

export interface SignedSafetyAttestation extends SafetyAttestation {
  kid?: string;
  issuerPubkey: string;
  signatureBase58: string;
  signatureScheme: typeof SIGNATURE_SCHEME;
}

export interface TierReceipt {
  schema: typeof TIER_SCHEMA;
  mint: string;
  tier: HolderTier;
  tierLabel: string;
  minPositionUsd: number;
  seekerHumanVerified: boolean;
  commitmentHex: string;
  issuedAt: string;
  expiresAt: string;
  digestHex: string;
}

export interface SignedTierReceipt extends TierReceipt {
  kid?: string;
  issuerPubkey: string;
  signatureBase58: string;
  signatureScheme: typeof SIGNATURE_SCHEME;
}

export interface SgtReceipt {
  schema: typeof SGT_SCHEMA;
  walletCommitmentHex: string;
  sgtMint: string;
  groupAddress: typeof SEEKER_SGT_GROUP_ADDRESS;
  skrDomain: string | null;
  verifiedAt: string;
  expiresAt: string;
  digestHex: string;
}

export interface SignedSgtReceipt extends SgtReceipt {
  kid?: string;
  issuerPubkey: string;
  signatureBase58: string;
  signatureScheme: typeof SIGNATURE_SCHEME;
}

export interface StampOnChainAnchor {
  network: 'mainnet-beta' | 'devnet';
  kind: 'tx_v1_pda' | 'memo_merkle' | 'sas_attestation';
  txSignature: string;
  merkleRootHex?: string | null;
  slot?: number | null;
}

export interface CallStampPayload {
  schema: typeof CALL_STAMP_SCHEMA;
  /** 8-character Base62 canonical short code (https://stampedfi.com/s/<stampId>) */
  stampId: string;
  /** Backing UUID of the call/post record */
  postId: string;
  kind: StampKind;
  mint: string;
  symbol: string;
  creatorHandle: string | null;
  /** Privacy-preserving SHA-256 commitment of creator wallet + salt (Zero-Dox) */
  walletCommitmentHex: string;
  /** Landed Solana buy/swap signature proving execution when kind is buy_call/position/closed_pnl */
  txSignature: string | null;
  slot: number | null;
  entryPriceUsd: number | null;
  supplyAtPost: number | null;
  entryMcapUsd: number | null;
  holderTier: HolderTier | null;
  /** SHA-256 hex of canonical thesis + invalidation text */
  thesisSha256: string;
  /** Optional 64-bit dHash perceptual visual fingerprint (16 hex chars) of the rendered card */
  artPhashHex: string | null;
  horizonDays: 1 | 7 | 30;
  issuedAt: string;
  anchor?: StampOnChainAnchor | null;
  digestHex: string;
}

export interface SignedCallStamp extends CallStampPayload {
  kid: string;
  issuerPubkey: string;
  signatureBase58: string;
  signatureScheme: typeof SIGNATURE_SCHEME;
}

const ALLOWED_SAS_SCHEMAS: readonly string[] = [SAS_SCHEMA];
const LEVELS: readonly SafetyLevel[] = ['ok', 'caution', 'risky', 'blocked', 'unknown'];
const STAMP_KINDS: readonly StampKind[] = ['buy_call', 'position', 'closed_pnl', 'spotlight', 'gift'];
const TIER_SPECS: Record<HolderTier, { minUsd: number; label: string; code: number }> = {
  Shrimp: { minUsd: 5, label: 'Shrimp ($5-$100)', code: 1 },
  Dolphin: { minUsd: 100, label: 'Dolphin ($100-$1K)', code: 2 },
  Shark: { minUsd: 1_000, label: 'Shark ($1K-$10K)', code: 3 },
  Whale: { minUsd: 10_000, label: 'Whale ($10K+)', code: 4 },
};
const CODE_TO_TIER: Record<number, HolderTier> = { 1: 'Shrimp', 2: 'Dolphin', 3: 'Shark', 4: 'Whale' };
const KIND_TO_CODE: Record<StampKind, number> = { buy_call: 0, position: 1, closed_pnl: 2, spotlight: 3, gift: 4 };
const CODE_TO_KIND: Record<number, StampKind> = { 0: 'buy_call', 1: 'position', 2: 'closed_pnl', 3: 'spotlight', 4: 'gift' };

const MINT_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const SIG_REGEX = /^[1-9A-HJ-NP-Za-km-z]{64,96}$/;
const HEX64_REGEX = /^[0-9a-f]{64}$/;
const HEX16_REGEX = /^[0-9a-f]{16}$/;
const SEED_HEX_REGEX = /^[0-9a-fA-F]{64}$/;
const STAMP_ID_REGEX = /^[0-9A-Za-z]{8}$/;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DEFAULT_CLOCK_SKEW_MS = 30_000;

export const tradeAllowedFor = (level: SafetyLevel): boolean => level === 'ok' || level === 'caution' || level === 'risky';
export const quickBuyAllowedFor = (level: SafetyLevel): boolean => level === 'ok' || level === 'caution';

function normalizeOpts(arg?: string | VerifyOptions): VerifyOptions {
  if (typeof arg === 'string') return { expectedIssuerPubkey: arg };
  return arg ?? {};
}

function decodeExact(b58: unknown, expectedLength: number): Uint8Array | null {
  if (typeof b58 !== 'string' || b58.length === 0 || b58.length > 120) return null;
  try {
    const bytes = bs58.decode(b58);
    return bytes.length === expectedLength ? bytes : null;
  } catch {
    return null;
  }
}

function isNotExpired(expiresAtIso: string | undefined, nowMs: number | undefined, clockSkewMs: number): boolean {
  if (!expiresAtIso) return true;
  const exp = Date.parse(expiresAtIso);
  if (Number.isNaN(exp)) return false;
  if (nowMs === undefined) return true;
  return nowMs <= exp + clockSkewMs;
}

export function sha256Hex(input: string | Uint8Array): string {
  return createHash('sha256').update(input).digest('hex');
}

// ---- Safety Attestation (stamped-sas-v1) ----

export function attestationDigest(core: {
  schema?: SasSchema;
  mint: string;
  level: SafetyLevel;
  coverageBps: number;
  flagIds: readonly string[];
  expiresAt?: string;
}): string {
  const schema = core.schema && ALLOWED_SAS_SCHEMAS.includes(core.schema) ? core.schema : SAS_SCHEMA;
  const canonical = core.expiresAt
    ? JSON.stringify({
        schema,
        mint: core.mint,
        level: core.level,
        coverageBps: core.coverageBps,
        flagIds: core.flagIds,
        expiresAt: core.expiresAt,
      })
    : JSON.stringify({
        schema,
        mint: core.mint,
        level: core.level,
        coverageBps: core.coverageBps,
        flagIds: core.flagIds,
      });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export function verifySafetyAttestationDigest(att: SafetyAttestation): boolean {
  if (!att || typeof att !== 'object') return false;
  if (!ALLOWED_SAS_SCHEMAS.includes(att.schema) || typeof att.mint !== 'string' || !MINT_REGEX.test(att.mint)) return false;
  if (!LEVELS.includes(att.level)) return false;
  if (!Number.isInteger(att.coverageBps) || att.coverageBps < 0 || att.coverageBps > 10_000) return false;
  if (!Array.isArray(att.flagIds) || !att.flagIds.every((f) => typeof f === 'string')) return false;
  for (let i = 1; i < att.flagIds.length; i++) {
    if (att.flagIds[i] <= att.flagIds[i - 1]) return false;
  }
  if (Number.isNaN(Date.parse(att.attestedAt))) return false;
  if (att.expiresAt !== undefined) {
    if (Number.isNaN(Date.parse(att.expiresAt)) || Date.parse(att.expiresAt) <= Date.parse(att.attestedAt)) return false;
  }
  if (typeof att.digestHex !== 'string' || !HEX64_REGEX.test(att.digestHex)) return false;
  if (att.tradeAllowed !== tradeAllowedFor(att.level) || att.quickBuyAllowed !== quickBuyAllowedFor(att.level)) return false;
  return att.digestHex === attestationDigest(att);
}

export function attestationSigningMessage(att: SafetyAttestation): Uint8Array {
  const payload = att.expiresAt
    ? {
        scheme: SIGNATURE_SCHEME,
        schema: att.schema,
        mint: att.mint,
        level: att.level,
        tradeAllowed: att.tradeAllowed,
        quickBuyAllowed: att.quickBuyAllowed,
        coverageBps: att.coverageBps,
        flagIds: att.flagIds,
        dangerCount: att.dangerCount,
        warnCount: att.warnCount,
        summary: att.summary,
        attestedAt: att.attestedAt,
        expiresAt: att.expiresAt,
        digestHex: att.digestHex,
      }
    : {
        scheme: SIGNATURE_SCHEME,
        schema: att.schema,
        mint: att.mint,
        level: att.level,
        tradeAllowed: att.tradeAllowed,
        quickBuyAllowed: att.quickBuyAllowed,
        coverageBps: att.coverageBps,
        flagIds: att.flagIds,
        dangerCount: att.dangerCount,
        warnCount: att.warnCount,
        summary: att.summary,
        attestedAt: att.attestedAt,
        digestHex: att.digestHex,
      };
  return new TextEncoder().encode(JSON.stringify(payload));
}

export function signSafetyAttestation(att: SafetyAttestation, secretSeedHex: string, kid?: string): SignedSafetyAttestation {
  if (!verifySafetyAttestationDigest(att)) throw new Error('invalid_attestation');
  if (!SEED_HEX_REGEX.test(secretSeedHex)) throw new Error('bad_secret_seed');
  const seed = Uint8Array.from(Buffer.from(secretSeedHex, 'hex'));
  const kp = nacl.sign.keyPair.fromSeed(seed);
  try {
    const clean: SafetyAttestation = {
      schema: att.schema,
      mint: att.mint,
      level: att.level,
      tradeAllowed: att.tradeAllowed,
      quickBuyAllowed: att.quickBuyAllowed,
      coverageBps: att.coverageBps,
      flagIds: [...att.flagIds],
      dangerCount: att.dangerCount,
      warnCount: att.warnCount,
      summary: att.summary,
      attestedAt: att.attestedAt,
      ...(att.expiresAt ? { expiresAt: att.expiresAt } : {}),
      digestHex: att.digestHex,
    };
    const sig = nacl.sign.detached(attestationSigningMessage(clean), kp.secretKey);
    return {
      ...clean,
      ...(kid ? { kid } : {}),
      issuerPubkey: bs58.encode(kp.publicKey),
      signatureBase58: bs58.encode(sig),
      signatureScheme: SIGNATURE_SCHEME,
    };
  } finally {
    kp.secretKey.fill(0);
    seed.fill(0);
  }
}

export function verifySignedSafetyAttestation(
  signed: SignedSafetyAttestation,
  expectedIssuerOrOpts?: string | VerifyOptions
): boolean {
  try {
    const opts = normalizeOpts(expectedIssuerOrOpts);
    const skew = opts.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
    if (!signed || typeof signed !== 'object' || !verifySafetyAttestationDigest(signed)) return false;
    if (signed.signatureScheme !== SIGNATURE_SCHEME) return false;
    const pub = decodeExact(signed.issuerPubkey, nacl.sign.publicKeyLength);
    const sig = decodeExact(signed.signatureBase58, nacl.sign.signatureLength);
    if (!pub || !sig) return false;
    if (opts.expectedIssuerPubkey !== undefined && signed.issuerPubkey !== opts.expectedIssuerPubkey) return false;
    if (signed.expiresAt && !isNotExpired(signed.expiresAt, opts.nowMs ?? Date.now(), skew)) return false;
    if (opts.maxAgeMs !== undefined) {
      const now = opts.nowMs ?? Date.now();
      if (now - Date.parse(signed.attestedAt) > opts.maxAgeMs + skew) return false;
    }
    return nacl.sign.detached.verify(attestationSigningMessage(signed), sig, pub);
  } catch {
    return false;
  }
}

// ---- Stamped Conviction Call & Card Proof (stamped-call-v1 · STP-1) ----

export function callStampDigest(core: Omit<CallStampPayload, 'digestHex' | 'anchor'>): string {
  const canonical = JSON.stringify({
    schema: CALL_STAMP_SCHEMA,
    stampId: core.stampId,
    postId: core.postId,
    kind: core.kind,
    mint: core.mint,
    symbol: core.symbol,
    creatorHandle: core.creatorHandle,
    walletCommitmentHex: core.walletCommitmentHex,
    txSignature: core.txSignature,
    slot: core.slot,
    entryPriceUsd: core.entryPriceUsd,
    supplyAtPost: core.supplyAtPost,
    entryMcapUsd: core.entryMcapUsd,
    holderTier: core.holderTier,
    thesisSha256: core.thesisSha256,
    artPhashHex: core.artPhashHex,
    horizonDays: core.horizonDays,
    issuedAt: core.issuedAt,
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

export function verifyCallStampDigest(stamp: CallStampPayload): boolean {
  if (!stamp || typeof stamp !== 'object' || stamp.schema !== CALL_STAMP_SCHEMA) return false;
  if (!STAMP_ID_REGEX.test(stamp.stampId) || !UUID_REGEX.test(stamp.postId)) return false;
  if (!STAMP_KINDS.includes(stamp.kind)) return false;
  if (!MINT_REGEX.test(stamp.mint) || typeof stamp.symbol !== 'string' || stamp.symbol.length < 1 || stamp.symbol.length > 20) return false;
  if (stamp.creatorHandle !== null && (typeof stamp.creatorHandle !== 'string' || stamp.creatorHandle.length > 64)) return false;
  if (!HEX64_REGEX.test(stamp.walletCommitmentHex) || !HEX64_REGEX.test(stamp.thesisSha256)) return false;
  if (stamp.txSignature !== null && !SIG_REGEX.test(stamp.txSignature)) return false;
  if (stamp.slot !== null && (!Number.isInteger(stamp.slot) || stamp.slot < 0)) return false;
  if (stamp.entryPriceUsd !== null && (!Number.isFinite(stamp.entryPriceUsd) || stamp.entryPriceUsd <= 0)) return false;
  if (stamp.supplyAtPost !== null && (!Number.isFinite(stamp.supplyAtPost) || stamp.supplyAtPost <= 0)) return false;
  if (stamp.entryMcapUsd !== null && (!Number.isFinite(stamp.entryMcapUsd) || stamp.entryMcapUsd <= 0)) return false;
  if (stamp.holderTier !== null && !(stamp.holderTier in TIER_SPECS)) return false;
  if (stamp.artPhashHex !== null && !HEX16_REGEX.test(stamp.artPhashHex)) return false;
  if (stamp.horizonDays !== 1 && stamp.horizonDays !== 7 && stamp.horizonDays !== 30) return false;
  if (Number.isNaN(Date.parse(stamp.issuedAt))) return false;
  if (!HEX64_REGEX.test(stamp.digestHex)) return false;
  return stamp.digestHex === callStampDigest(stamp);
}

export function callStampSigningMessage(stamp: CallStampPayload, kid: string): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      scheme: SIGNATURE_SCHEME,
      kid,
      schema: stamp.schema,
      stampId: stamp.stampId,
      postId: stamp.postId,
      kind: stamp.kind,
      mint: stamp.mint,
      symbol: stamp.symbol,
      creatorHandle: stamp.creatorHandle,
      walletCommitmentHex: stamp.walletCommitmentHex,
      txSignature: stamp.txSignature,
      slot: stamp.slot,
      entryPriceUsd: stamp.entryPriceUsd,
      supplyAtPost: stamp.supplyAtPost,
      entryMcapUsd: stamp.entryMcapUsd,
      holderTier: stamp.holderTier,
      thesisSha256: stamp.thesisSha256,
      artPhashHex: stamp.artPhashHex,
      horizonDays: stamp.horizonDays,
      issuedAt: stamp.issuedAt,
      digestHex: stamp.digestHex,
    })
  );
}

export function signCallStamp(
  core: Omit<CallStampPayload, 'digestHex'>,
  secretSeedHex: string,
  kid = 'sf-ed25519-v1'
): SignedCallStamp {
  if (!SEED_HEX_REGEX.test(secretSeedHex)) throw new Error('bad_secret_seed');
  const digestHex = callStampDigest(core);
  const full: CallStampPayload = { ...core, digestHex };
  if (!verifyCallStampDigest(full)) throw new Error('invalid_call_stamp');
  const seed = Uint8Array.from(Buffer.from(secretSeedHex, 'hex'));
  const kp = nacl.sign.keyPair.fromSeed(seed);
  try {
    const sig = nacl.sign.detached(callStampSigningMessage(full, kid), kp.secretKey);
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

export function verifySignedCallStamp(
  signed: SignedCallStamp,
  expectedIssuerOrOpts?: string | VerifyOptions
): boolean {
  try {
    const opts = normalizeOpts(expectedIssuerOrOpts);
    if (!signed || typeof signed !== 'object' || !verifyCallStampDigest(signed)) return false;
    if (signed.signatureScheme !== SIGNATURE_SCHEME || typeof signed.kid !== 'string' || !signed.kid) return false;
    const pub = decodeExact(signed.issuerPubkey, nacl.sign.publicKeyLength);
    const sig = decodeExact(signed.signatureBase58, nacl.sign.signatureLength);
    if (!pub || !sig) return false;
    if (opts.expectedIssuerPubkey !== undefined && signed.issuerPubkey !== opts.expectedIssuerPubkey) return false;
    return nacl.sign.detached.verify(callStampSigningMessage(signed, signed.kid), sig, pub);
  } catch {
    return false;
  }
}

/**
 * Deterministic 48-bit Pixel-DNA signature tag binding an exported card's invisible
 * watermark directly to the signed `stamped-call-v1` envelope.
 */
export function computePixelDnaTagHex(signed: Pick<SignedCallStamp, 'stampId' | 'digestHex' | 'signatureBase58'>): string {
  return createHash('sha256')
    .update(`stp1-pixel-dna|${signed.stampId}|${signed.digestHex}|${signed.signatureBase58}`, 'utf8')
    .digest('hex')
    .slice(0, 12); // 48 bits = 6 bytes = 12 hex chars
}

/**
 * Deterministic 168-byte binary Card Genome (`CardGenomeV1`) designed to fit inside a
 * single 4,096-byte Solana Transaction v1 (`SIMD-0296`/`0385`) alongside a DEX swap
 * and Light Protocol Compressed PDA proof. Any client can reconstruct card proof fields
 * directly from Solana L1 bytes.
 *
 * Layout (168 bytes, little-endian):
 *   [0]       version (u8 = 1)
 *   [1]       kind (u8: 0..4)
 *   [2]       holderTier (u8: 0=none, 1..4)
 *   [3]       horizonDays (u8: 1 | 7 | 30)
 *   [4..12]   stampId ASCII (8 bytes)
 *   [12..44]  mint Pubkey (32 bytes)
 *   [44..76]  walletCommitment (32 bytes)
 *   [76..108] thesisSha256 (32 bytes)
 *   [108..116] artPhash (8 bytes, zeros if absent)
 *   [116..124] slot (u64)
 *   [124..132] issuedAtUnixSec (i64)
 *   [132..140] entryMcapUsdCents (u64)
 *   [140..148] entryPriceUsdE9 (u64)
 *   [148..168] symbol UTF-8 zero-padded (20 bytes)
 */
export const CARD_GENOME_V1_BYTES = 168;

export function encodeCardGenomeV1(stamp: CallStampPayload): Uint8Array {
  if (!verifyCallStampDigest(stamp)) throw new Error('invalid_call_stamp');
  const mintBytes = decodeExact(stamp.mint, 32);
  if (!mintBytes) throw new Error('invalid_mint_bytes');
  const out = new Uint8Array(CARD_GENOME_V1_BYTES);
  const view = new DataView(out.buffer);
  out[0] = CARD_GENOME_VERSION;
  out[1] = KIND_TO_CODE[stamp.kind];
  out[2] = stamp.holderTier ? TIER_SPECS[stamp.holderTier].code : 0;
  out[3] = stamp.horizonDays;
  out.set(new TextEncoder().encode(stamp.stampId), 4);
  out.set(mintBytes, 12);
  out.set(Buffer.from(stamp.walletCommitmentHex, 'hex'), 44);
  out.set(Buffer.from(stamp.thesisSha256, 'hex'), 76);
  if (stamp.artPhashHex) out.set(Buffer.from(stamp.artPhashHex, 'hex'), 108);
  view.setBigUint64(116, BigInt(stamp.slot ?? 0), true);
  view.setBigInt64(124, BigInt(Math.floor(Date.parse(stamp.issuedAt) / 1000)), true);
  view.setBigUint64(132, BigInt(Math.max(0, Math.round((stamp.entryMcapUsd ?? 0) * 100))), true);
  view.setBigUint64(140, BigInt(Math.max(0, Math.round((stamp.entryPriceUsd ?? 0) * 1e9))), true);
  const symBytes = new TextEncoder().encode(stamp.symbol.slice(0, 20));
  out.set(symBytes, 148);
  return out;
}

export interface DecodedCardGenomeV1 {
  version: number;
  kind: StampKind;
  holderTier: HolderTier | null;
  horizonDays: 1 | 7 | 30;
  stampId: string;
  mint: string;
  walletCommitmentHex: string;
  thesisSha256: string;
  artPhashHex: string | null;
  slot: number | null;
  issuedAtUnixSec: number;
  entryMcapUsd: number | null;
  entryPriceUsd: number | null;
  symbol: string;
}

export function decodeCardGenomeV1(bytes: Uint8Array): DecodedCardGenomeV1 | null {
  if (!(bytes instanceof Uint8Array) || bytes.length !== CARD_GENOME_V1_BYTES) return null;
  if (bytes[0] !== CARD_GENOME_VERSION) return null;
  const kind = CODE_TO_KIND[bytes[1]];
  if (!kind) return null;
  const tierCode = bytes[2];
  const holderTier = tierCode === 0 ? null : CODE_TO_TIER[tierCode] ?? null;
  const horizonRaw = bytes[3];
  if (horizonRaw !== 1 && horizonRaw !== 7 && horizonRaw !== 30) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const stampId = new TextDecoder().decode(bytes.subarray(4, 12));
  if (!STAMP_ID_REGEX.test(stampId)) return null;
  const mint = bs58.encode(bytes.subarray(12, 44));
  const walletCommitmentHex = Buffer.from(bytes.subarray(44, 76)).toString('hex');
  const thesisSha256 = Buffer.from(bytes.subarray(76, 108)).toString('hex');
  const phashSlice = bytes.subarray(108, 116);
  const artPhashHex = phashSlice.some((b) => b !== 0) ? Buffer.from(phashSlice).toString('hex') : null;
  const slotBig = view.getBigUint64(116, true);
  const issuedAtUnixSec = Number(view.getBigInt64(124, true));
  const mcapCents = Number(view.getBigUint64(132, true));
  const priceE9 = Number(view.getBigUint64(140, true));
  const symSlice = bytes.subarray(148, 168);
  const zeroIdx = symSlice.indexOf(0);
  const symbol = new TextDecoder().decode(zeroIdx === -1 ? symSlice : symSlice.subarray(0, zeroIdx));
  return {
    version: bytes[0],
    kind,
    holderTier,
    horizonDays: horizonRaw,
    stampId,
    mint,
    walletCommitmentHex,
    thesisSha256,
    artPhashHex,
    slot: slotBig > 0n ? Number(slotBig) : null,
    issuedAtUnixSec,
    entryMcapUsd: mcapCents > 0 ? mcapCents / 100 : null,
    entryPriceUsd: priceE9 > 0 ? priceE9 / 1e9 : null,
    symbol,
  };
}

// ---- Zero-Dox Tier Receipt Verification (stamped-tier-v1) ----

export function tierReceiptDigest(r: Omit<TierReceipt, 'digestHex' | 'tierLabel'>): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        schema: TIER_SCHEMA,
        mint: r.mint,
        tier: r.tier,
        minPositionUsd: r.minPositionUsd,
        seekerHumanVerified: r.seekerHumanVerified,
        commitmentHex: r.commitmentHex,
        issuedAt: r.issuedAt,
        expiresAt: r.expiresAt,
      }),
      'utf8'
    )
    .digest('hex');
}

export function verifyTierReceiptDigest(r: TierReceipt): boolean {
  if (!r || typeof r !== 'object' || r.schema !== TIER_SCHEMA) return false;
  if (typeof r.mint !== 'string' || !MINT_REGEX.test(r.mint)) return false;
  const spec = TIER_SPECS[r.tier];
  if (!spec || r.minPositionUsd !== spec.minUsd || r.tierLabel !== spec.label) return false;
  if (typeof r.seekerHumanVerified !== 'boolean') return false;
  if (typeof r.commitmentHex !== 'string' || !HEX64_REGEX.test(r.commitmentHex)) return false;
  if (Number.isNaN(Date.parse(r.issuedAt)) || Number.isNaN(Date.parse(r.expiresAt))) return false;
  if (Date.parse(r.expiresAt) <= Date.parse(r.issuedAt)) return false;
  return r.digestHex === tierReceiptDigest(r);
}

export function signTierReceipt(
  input: { mint: string; tier: HolderTier; seekerHumanVerified: boolean; commitmentHex: string; issuedAt: string; expiresAt: string },
  secretSeedHex: string,
  kid?: string
): SignedTierReceipt {
  if (!SEED_HEX_REGEX.test(secretSeedHex)) throw new Error('bad_secret_seed');
  const spec = TIER_SPECS[input.tier];
  const core: Omit<TierReceipt, 'digestHex'> = {
    schema: TIER_SCHEMA,
    mint: input.mint,
    tier: input.tier,
    tierLabel: spec.label,
    minPositionUsd: spec.minUsd,
    seekerHumanVerified: input.seekerHumanVerified,
    commitmentHex: input.commitmentHex,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
  };
  const receipt: TierReceipt = { ...core, digestHex: tierReceiptDigest(core) };
  if (!verifyTierReceiptDigest(receipt)) throw new Error('invalid_tier_receipt');
  const seed = Uint8Array.from(Buffer.from(secretSeedHex, 'hex'));
  const kp = nacl.sign.keyPair.fromSeed(seed);
  try {
    const msg = new TextEncoder().encode(
      JSON.stringify({
        scheme: SIGNATURE_SCHEME,
        schema: receipt.schema,
        mint: receipt.mint,
        tier: receipt.tier,
        tierLabel: receipt.tierLabel,
        minPositionUsd: receipt.minPositionUsd,
        seekerHumanVerified: receipt.seekerHumanVerified,
        commitmentHex: receipt.commitmentHex,
        issuedAt: receipt.issuedAt,
        expiresAt: receipt.expiresAt,
        digestHex: receipt.digestHex,
      })
    );
    const sig = nacl.sign.detached(msg, kp.secretKey);
    return {
      ...receipt,
      ...(kid ? { kid } : {}),
      issuerPubkey: bs58.encode(kp.publicKey),
      signatureBase58: bs58.encode(sig),
      signatureScheme: SIGNATURE_SCHEME,
    };
  } finally {
    kp.secretKey.fill(0);
    seed.fill(0);
  }
}

export function verifySignedTierReceipt(
  signed: SignedTierReceipt,
  expectedIssuerOrOpts?: string | VerifyOptions
): boolean {
  try {
    const opts = normalizeOpts(expectedIssuerOrOpts);
    const skew = opts.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
    if (!signed || typeof signed !== 'object' || !verifyTierReceiptDigest(signed)) return false;
    if (signed.signatureScheme !== SIGNATURE_SCHEME) return false;
    const pub = decodeExact(signed.issuerPubkey, nacl.sign.publicKeyLength);
    const sig = decodeExact(signed.signatureBase58, nacl.sign.signatureLength);
    if (!pub || !sig) return false;
    if (opts.expectedIssuerPubkey !== undefined && signed.issuerPubkey !== opts.expectedIssuerPubkey) return false;
    if (!isNotExpired(signed.expiresAt, opts.nowMs ?? Date.now(), skew)) return false;
    const msg = new TextEncoder().encode(
      JSON.stringify({
        scheme: SIGNATURE_SCHEME,
        schema: signed.schema,
        mint: signed.mint,
        tier: signed.tier,
        tierLabel: signed.tierLabel,
        minPositionUsd: signed.minPositionUsd,
        seekerHumanVerified: signed.seekerHumanVerified,
        commitmentHex: signed.commitmentHex,
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

// ---- Seeker Genesis Token Hardware-Human Verification (stamped-sgt-v1) ----

export function sgtReceiptDigest(r: Omit<SgtReceipt, 'digestHex'>): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        schema: SGT_SCHEMA,
        walletCommitmentHex: r.walletCommitmentHex,
        sgtMint: r.sgtMint,
        groupAddress: SEEKER_SGT_GROUP_ADDRESS,
        skrDomain: r.skrDomain,
        verifiedAt: r.verifiedAt,
        expiresAt: r.expiresAt,
      }),
      'utf8'
    )
    .digest('hex');
}

export function verifySgtReceiptDigest(r: SgtReceipt): boolean {
  if (!r || typeof r !== 'object' || r.schema !== SGT_SCHEMA) return false;
  if (r.groupAddress !== SEEKER_SGT_GROUP_ADDRESS) return false;
  if (typeof r.walletCommitmentHex !== 'string' || !HEX64_REGEX.test(r.walletCommitmentHex)) return false;
  if (typeof r.sgtMint !== 'string' || !MINT_REGEX.test(r.sgtMint)) return false;
  if (r.skrDomain !== null && !/^[a-z0-9-]{1,32}\.skr$/.test(r.skrDomain)) return false;
  if (Number.isNaN(Date.parse(r.verifiedAt)) || Number.isNaN(Date.parse(r.expiresAt))) return false;
  if (Date.parse(r.expiresAt) <= Date.parse(r.verifiedAt)) return false;
  return r.digestHex === sgtReceiptDigest(r);
}

export function signSgtReceipt(
  input: { walletCommitmentHex: string; sgtMint: string; skrDomain: string | null; verifiedAt: string; expiresAt: string },
  secretSeedHex: string,
  kid?: string
): SignedSgtReceipt {
  if (!SEED_HEX_REGEX.test(secretSeedHex)) throw new Error('bad_secret_seed');
  const core: Omit<SgtReceipt, 'digestHex'> = {
    schema: SGT_SCHEMA,
    walletCommitmentHex: input.walletCommitmentHex,
    sgtMint: input.sgtMint,
    groupAddress: SEEKER_SGT_GROUP_ADDRESS,
    skrDomain: input.skrDomain,
    verifiedAt: input.verifiedAt,
    expiresAt: input.expiresAt,
  };
  const receipt: SgtReceipt = { ...core, digestHex: sgtReceiptDigest(core) };
  if (!verifySgtReceiptDigest(receipt)) throw new Error('invalid_sgt_receipt');
  const seed = Uint8Array.from(Buffer.from(secretSeedHex, 'hex'));
  const kp = nacl.sign.keyPair.fromSeed(seed);
  try {
    const msg = new TextEncoder().encode(
      JSON.stringify({
        scheme: SIGNATURE_SCHEME,
        schema: receipt.schema,
        walletCommitmentHex: receipt.walletCommitmentHex,
        sgtMint: receipt.sgtMint,
        groupAddress: receipt.groupAddress,
        skrDomain: receipt.skrDomain,
        verifiedAt: receipt.verifiedAt,
        expiresAt: receipt.expiresAt,
        digestHex: receipt.digestHex,
      })
    );
    const sig = nacl.sign.detached(msg, kp.secretKey);
    return {
      ...receipt,
      ...(kid ? { kid } : {}),
      issuerPubkey: bs58.encode(kp.publicKey),
      signatureBase58: bs58.encode(sig),
      signatureScheme: SIGNATURE_SCHEME,
    };
  } finally {
    kp.secretKey.fill(0);
    seed.fill(0);
  }
}

export function verifySignedSgtReceipt(
  signed: SignedSgtReceipt,
  expectedIssuerOrOpts?: string | VerifyOptions
): boolean {
  try {
    const opts = normalizeOpts(expectedIssuerOrOpts);
    const skew = opts.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
    if (!signed || typeof signed !== 'object' || !verifySgtReceiptDigest(signed)) return false;
    if (signed.signatureScheme !== SIGNATURE_SCHEME) return false;
    const pub = decodeExact(signed.issuerPubkey, nacl.sign.publicKeyLength);
    const sig = decodeExact(signed.signatureBase58, nacl.sign.signatureLength);
    if (!pub || !sig) return false;
    if (opts.expectedIssuerPubkey !== undefined && signed.issuerPubkey !== opts.expectedIssuerPubkey) return false;
    if (!isNotExpired(signed.expiresAt, opts.nowMs ?? Date.now(), skew)) return false;
    const msg = new TextEncoder().encode(
      JSON.stringify({
        scheme: SIGNATURE_SCHEME,
        schema: signed.schema,
        walletCommitmentHex: signed.walletCommitmentHex,
        sgtMint: signed.sgtMint,
        groupAddress: signed.groupAddress,
        skrDomain: signed.skrDomain,
        verifiedAt: signed.verifiedAt,
        expiresAt: signed.expiresAt,
        digestHex: signed.digestHex,
      })
    );
    return nacl.sign.detached.verify(msg, sig, pub);
  } catch {
    return false;
  }
}

// ---- Solana Actions / Blink Pre-Execution Guard ----

export interface BlinkGuardResult {
  allowed: boolean;
  actionHttpsUrl: string | null;
  extractedMint: string | null;
  reason: string;
}

export function guardSolanaBlinkUrl(
  rawBlinkOrActionUrl: string,
  attestation?: SafetyAttestation | SignedSafetyAttestation,
  expectedIssuerOrOpts?: string | VerifyOptions
): BlinkGuardResult {
  try {
    const opts = normalizeOpts(expectedIssuerOrOpts);
    const requireSig = opts.requireSignature ?? true;
    const trimmed = rawBlinkOrActionUrl.trim();
    let target = trimmed;
    if (trimmed.startsWith('solana-action:')) {
      target = decodeURIComponent(trimmed.slice('solana-action:'.length));
    } else {
      const parsedOuter = new URL(trimmed);
      const actionParam = parsedOuter.searchParams.get('action');
      if (actionParam && actionParam.startsWith('solana-action:')) {
        target = decodeURIComponent(actionParam.slice('solana-action:'.length));
      }
    }

    const actionUrl = new URL(target);
    if (actionUrl.protocol !== 'https:') {
      return { allowed: false, actionHttpsUrl: null, extractedMint: null, reason: 'Blink action URL must use HTTPS.' };
    }

    const mintParam = actionUrl.searchParams.get('mint');
    const pathMatch = actionUrl.pathname.split('/').find((seg) => MINT_REGEX.test(seg)) ?? null;
    const extractedMint = mintParam && MINT_REGEX.test(mintParam) ? mintParam : pathMatch;

    if (attestation) {
      const isSigned = 'signatureBase58' in attestation && Boolean(attestation.signatureBase58);
      if (requireSig && !isSigned) {
        return {
          allowed: false,
          actionHttpsUrl: actionUrl.toString(),
          extractedMint,
          reason: 'Unsigned stamped-sas-v1 attestation rejected (Ed25519 signature required).',
        };
      }
      const intact = isSigned
        ? verifySignedSafetyAttestation(attestation as SignedSafetyAttestation, opts)
        : verifySafetyAttestationDigest(attestation);
      if (!intact) {
        return {
          allowed: false,
          actionHttpsUrl: actionUrl.toString(),
          extractedMint,
          reason: 'Invalid, expired, or tampered stamped-sas-v1 safety attestation.',
        };
      }
      if (extractedMint && attestation.mint !== extractedMint) {
        return {
          allowed: false,
          actionHttpsUrl: actionUrl.toString(),
          extractedMint,
          reason: 'Attestation mint does not match Blink target mint.',
        };
      }
      if (!attestation.tradeAllowed) {
        return {
          allowed: false,
          actionHttpsUrl: actionUrl.toString(),
          extractedMint,
          reason: `Blocked by StampedFi Safety Firewall (${attestation.level}: ${attestation.flagIds.join(', ') || 'restricted'}).`,
        };
      }
    }

    return {
      allowed: true,
      actionHttpsUrl: actionUrl.toString(),
      extractedMint,
      reason: 'Blink passed URL & StampedFi pre-execution guard.',
    };
  } catch {
    return { allowed: false, actionHttpsUrl: null, extractedMint: null, reason: 'Malformed Blink or Solana Action URL.' };
  }
}

export * from './solanaV1.js';
export * from './passport.js';
