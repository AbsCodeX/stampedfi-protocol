/**
 * @stampedfi/sas-verifier — Official MIT Open-Source Cryptographic Verifier SDK by STAMPED Labs, Inc.
 *
 * Verifies in <1ms offline (zero RPC calls, zero proprietary backend secrets):
 * 1. `stamped-sas-v1` Solana token safety attestations
 * 2. `stamped-tier-v1` Zero-Dox holder tier receipts (Shrimp / Dolphin / Shark / Whale)
 * 3. `stamped-sgt-v1` Solana Mobile Seeker Genesis Token Hardware-Human badges
 * 4. `guardSolanaBlinkUrl` Solana Actions / Blink URL pre-execution safety gate
 */
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import bs58 from 'bs58';

export const SAS_SCHEMA = 'stamped-sas-v1' as const;
export const TIER_SCHEMA = 'stamped-tier-v1' as const;
export const SGT_SCHEMA = 'stamped-sgt-v1' as const;
export const SIGNATURE_SCHEME = 'ed25519-v1' as const;
export const SEEKER_SGT_GROUP_ADDRESS = 'GT22s89nU4iWFkNXj1Bw6uYhJJWDRPpShHt4Bk8f99Te' as const;

export type SafetyLevel = 'ok' | 'caution' | 'risky' | 'blocked' | 'unknown';
export type SasSchema = typeof SAS_SCHEMA;
export type HolderTier = 'Shrimp' | 'Dolphin' | 'Shark' | 'Whale';

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
  digestHex: string;
}

export interface SignedSafetyAttestation extends SafetyAttestation {
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
  issuerPubkey: string;
  signatureBase58: string;
  signatureScheme: typeof SIGNATURE_SCHEME;
}

const ALLOWED_SAS_SCHEMAS: readonly string[] = [SAS_SCHEMA];
const LEVELS: readonly SafetyLevel[] = ['ok', 'caution', 'risky', 'blocked', 'unknown'];
const TIER_SPECS: Record<HolderTier, { minUsd: number; label: string }> = {
  Shrimp: { minUsd: 5, label: 'Shrimp ($5-$100)' },
  Dolphin: { minUsd: 100, label: 'Dolphin ($100-$1K)' },
  Shark: { minUsd: 1_000, label: 'Shark ($1K-$10K)' },
  Whale: { minUsd: 10_000, label: 'Whale ($10K+)' },
};

const MINT_REGEX = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const HEX64_REGEX = /^[0-9a-f]{64}$/;
const SEED_HEX_REGEX = /^[0-9a-fA-F]{64}$/;

const tradeAllowedFor = (level: SafetyLevel): boolean => level === 'ok' || level === 'caution' || level === 'risky';
const quickBuyAllowedFor = (level: SafetyLevel): boolean => level === 'ok' || level === 'caution';

function decodeExact(b58: unknown, expectedLength: number): Uint8Array | null {
  if (typeof b58 !== 'string' || b58.length === 0 || b58.length > 120) return null;
  try {
    const bytes = bs58.decode(b58);
    return bytes.length === expectedLength ? bytes : null;
  } catch {
    return null;
  }
}

export function attestationDigest(core: {
  schema?: SasSchema;
  mint: string;
  level: SafetyLevel;
  coverageBps: number;
  flagIds: readonly string[];
}): string {
  const schema = core.schema && ALLOWED_SAS_SCHEMAS.includes(core.schema) ? core.schema : SAS_SCHEMA;
  const canonical = JSON.stringify({
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
  // Require strictly sorted unique flagIds to prevent malleability
  for (let i = 1; i < att.flagIds.length; i++) {
    if (att.flagIds[i] <= att.flagIds[i - 1]) return false;
  }
  if (typeof att.digestHex !== 'string' || !HEX64_REGEX.test(att.digestHex)) return false;
  if (att.tradeAllowed !== tradeAllowedFor(att.level) || att.quickBuyAllowed !== quickBuyAllowedFor(att.level)) return false;
  return att.digestHex === attestationDigest(att);
}

export function attestationSigningMessage(att: SafetyAttestation): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
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
    })
  );
}

export function signSafetyAttestation(att: SafetyAttestation, secretSeedHex: string): SignedSafetyAttestation {
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
      digestHex: att.digestHex,
    };
    const sig = nacl.sign.detached(attestationSigningMessage(clean), kp.secretKey);
    return {
      ...clean,
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
  expectedIssuerPubkey?: string
): boolean {
  try {
    if (!signed || typeof signed !== 'object' || !verifySafetyAttestationDigest(signed)) return false;
    if (signed.signatureScheme !== SIGNATURE_SCHEME) return false;
    const pub = decodeExact(signed.issuerPubkey, nacl.sign.publicKeyLength);
    const sig = decodeExact(signed.signatureBase58, nacl.sign.signatureLength);
    if (!pub || !sig) return false;
    if (expectedIssuerPubkey !== undefined && signed.issuerPubkey !== expectedIssuerPubkey) return false;
    return nacl.sign.detached.verify(attestationSigningMessage(signed), sig, pub);
  } catch {
    return false;
  }
}

// ---- Zero-Dox Tier Receipt Verification (stamped-tier-v1) ----

export function verifyTierReceiptDigest(r: TierReceipt): boolean {
  if (!r || typeof r !== 'object' || r.schema !== TIER_SCHEMA) return false;
  if (typeof r.mint !== 'string' || !MINT_REGEX.test(r.mint)) return false;
  const spec = TIER_SPECS[r.tier];
  if (!spec || r.minPositionUsd !== spec.minUsd || r.tierLabel !== spec.label) return false;
  if (typeof r.seekerHumanVerified !== 'boolean') return false;
  if (typeof r.commitmentHex !== 'string' || !HEX64_REGEX.test(r.commitmentHex)) return false;
  if (Number.isNaN(Date.parse(r.issuedAt)) || Number.isNaN(Date.parse(r.expiresAt))) return false;
  if (Date.parse(r.expiresAt) <= Date.parse(r.issuedAt)) return false;
  const expectedDigest = createHash('sha256')
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
  return r.digestHex === expectedDigest;
}

export function verifySignedTierReceipt(signed: SignedTierReceipt, expectedIssuerPubkey?: string): boolean {
  try {
    if (!signed || typeof signed !== 'object' || !verifyTierReceiptDigest(signed)) return false;
    if (signed.signatureScheme !== SIGNATURE_SCHEME) return false;
    const pub = decodeExact(signed.issuerPubkey, nacl.sign.publicKeyLength);
    const sig = decodeExact(signed.signatureBase58, nacl.sign.signatureLength);
    if (!pub || !sig) return false;
    if (expectedIssuerPubkey !== undefined && signed.issuerPubkey !== expectedIssuerPubkey) return false;
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

export function verifySgtReceiptDigest(r: SgtReceipt): boolean {
  if (!r || typeof r !== 'object' || r.schema !== SGT_SCHEMA) return false;
  if (r.groupAddress !== SEEKER_SGT_GROUP_ADDRESS) return false;
  if (typeof r.walletCommitmentHex !== 'string' || !HEX64_REGEX.test(r.walletCommitmentHex)) return false;
  if (typeof r.sgtMint !== 'string' || !MINT_REGEX.test(r.sgtMint)) return false;
  if (r.skrDomain !== null && !/^[a-z0-9-]{1,32}\.skr$/.test(r.skrDomain)) return false;
  if (Number.isNaN(Date.parse(r.verifiedAt)) || Number.isNaN(Date.parse(r.expiresAt))) return false;
  const expectedDigest = createHash('sha256')
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
  return r.digestHex === expectedDigest;
}

export function verifySignedSgtReceipt(signed: SignedSgtReceipt, expectedIssuerPubkey?: string): boolean {
  try {
    if (!signed || typeof signed !== 'object' || !verifySgtReceiptDigest(signed)) return false;
    if (signed.signatureScheme !== SIGNATURE_SCHEME) return false;
    const pub = decodeExact(signed.issuerPubkey, nacl.sign.publicKeyLength);
    const sig = decodeExact(signed.signatureBase58, nacl.sign.signatureLength);
    if (!pub || !sig) return false;
    if (expectedIssuerPubkey !== undefined && signed.issuerPubkey !== expectedIssuerPubkey) return false;
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
  expectedIssuerPubkey?: string
): BlinkGuardResult {
  try {
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

    // Extract Base58 Solana mint candidate from path segments or `mint` query param
    const mintParam = actionUrl.searchParams.get('mint');
    const pathMatch = actionUrl.pathname.split('/').find((seg) => MINT_REGEX.test(seg)) ?? null;
    const extractedMint = mintParam && MINT_REGEX.test(mintParam) ? mintParam : pathMatch;

    if (attestation) {
      const intact =
        'signatureBase58' in attestation
          ? verifySignedSafetyAttestation(attestation, expectedIssuerPubkey)
          : verifySafetyAttestationDigest(attestation);
      if (!intact) {
        return {
          allowed: false,
          actionHttpsUrl: actionUrl.toString(),
          extractedMint,
          reason: 'Invalid or tampered stamped-sas-v1 safety attestation.',
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
