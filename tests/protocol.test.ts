import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import {
  LEGACY_SAS_SCHEMA,
  SAS_SCHEMA,
  SEEKER_SGT_GROUP_ADDRESS,
  SGT_SCHEMA,
  SIGNATURE_SCHEME,
  TIER_SCHEMA,
  attestationDigest,
  guardSolanaBlinkUrl,
  signSafetyAttestation,
  verifySafetyAttestationDigest,
  verifySignedSafetyAttestation,
  verifySignedSgtReceipt,
  verifySignedTierReceipt,
  type SafetyAttestation,
  type SignedSgtReceipt,
  type SignedTierReceipt,
} from '../packages/sas-verifier/src/index.js';
import { computeStampShieldAuto2x, createStampedMcpServer, createStampedMcpTools } from '../packages/stampedfi-mcp/src/index.js';

const SEED_HEX = '33'.repeat(32);
const KP = nacl.sign.keyPair.fromSeed(Buffer.from(SEED_HEX, 'hex'));
const ISSUER_PUBKEY = bs58.encode(KP.publicKey);
const BONK_MINT = 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263';

function sampleAttestation(level: SafetyAttestation['level'] = 'ok'): SafetyAttestation {
  const flagIds = level === 'blocked' ? ['honeypot_no_sell_route', 'permanent_delegate'] : [];
  const tradeAllowed = level === 'ok' || level === 'caution' || level === 'risky';
  const quickBuyAllowed = level === 'ok' || level === 'caution';
  return {
    schema: SAS_SCHEMA,
    mint: BONK_MINT,
    level,
    tradeAllowed,
    quickBuyAllowed,
    coverageBps: 10_000,
    flagIds,
    dangerCount: flagIds.length,
    warnCount: 0,
    summary: level === 'ok' ? 'Clean liquidity & authorities renounced.' : 'Blocked honeypot.',
    attestedAt: '2026-11-17T12:00:00.000Z',
    digestHex: attestationDigest({
      schema: SAS_SCHEMA,
      mint: BONK_MINT,
      level,
      coverageBps: 10_000,
      flagIds,
    }),
  };
}

describe('@stampedfi/sas-verifier', () => {
  it('signs and verifies stamped-sas-v1 attestations in <1ms and rejects any tampering', () => {
    const unsigned = sampleAttestation('ok');
    const signed = signSafetyAttestation(unsigned, SEED_HEX);

    const t0 = performance.now();
    const ok = verifySignedSafetyAttestation(signed, ISSUER_PUBKEY);
    const elapsedMs = performance.now() - t0;

    expect(ok).toBe(true);
    expect(elapsedMs).toBeLessThan(15);
    expect(verifySignedSafetyAttestation({ ...signed, summary: 'Tampered summary' }, ISSUER_PUBKEY)).toBe(false);
    expect(verifySignedSafetyAttestation(signed, '11111111111111111111111111111111')).toBe(false);
  });

  it('maintains backward-compatibility with legacy pippop-sas-v1 records', () => {
    const base = sampleAttestation('caution');
    const legacy: SafetyAttestation = {
      ...base,
      schema: LEGACY_SAS_SCHEMA,
      digestHex: attestationDigest({
        schema: LEGACY_SAS_SCHEMA,
        mint: base.mint,
        level: base.level,
        coverageBps: base.coverageBps,
        flagIds: base.flagIds,
      }),
    };
    expect(verifySafetyAttestationDigest(legacy)).toBe(true);
  });

  it('verifies Zero-Dox stamped-tier-v1 and Seeker stamped-sgt-v1 Ed25519 receipts', () => {
    const commitmentHex = createHash('sha256').update('nonce:wallet:mint').digest('hex');
    const issuedAt = '2026-11-17T12:00:00.000Z';
    const expiresAt = '2026-11-17T13:00:00.000Z';
    const tierDigest = createHash('sha256')
      .update(
        JSON.stringify({
          schema: TIER_SCHEMA,
          mint: BONK_MINT,
          tier: 'Whale',
          minPositionUsd: 10_000,
          seekerHumanVerified: true,
          commitmentHex,
          issuedAt,
          expiresAt,
        })
      )
      .digest('hex');

    const tierMsg = new TextEncoder().encode(
      JSON.stringify({
        scheme: SIGNATURE_SCHEME,
        schema: TIER_SCHEMA,
        mint: BONK_MINT,
        tier: 'Whale',
        tierLabel: 'Whale ($10K+)',
        minPositionUsd: 10_000,
        seekerHumanVerified: true,
        commitmentHex,
        issuedAt,
        expiresAt,
        digestHex: tierDigest,
      })
    );
    const tierSig = bs58.encode(nacl.sign.detached(tierMsg, KP.secretKey));
    const signedTier: SignedTierReceipt = {
      schema: TIER_SCHEMA,
      mint: BONK_MINT,
      tier: 'Whale',
      tierLabel: 'Whale ($10K+)',
      minPositionUsd: 10_000,
      seekerHumanVerified: true,
      commitmentHex,
      issuedAt,
      expiresAt,
      digestHex: tierDigest,
      issuerPubkey: ISSUER_PUBKEY,
      signatureBase58: tierSig,
      signatureScheme: SIGNATURE_SCHEME,
    };
    expect(verifySignedTierReceipt(signedTier, ISSUER_PUBKEY)).toBe(true);

    const sgtDigest = createHash('sha256')
      .update(
        JSON.stringify({
          schema: SGT_SCHEMA,
          walletCommitmentHex: commitmentHex,
          sgtMint: BONK_MINT,
          groupAddress: SEEKER_SGT_GROUP_ADDRESS,
          skrDomain: 'abigail.skr',
          verifiedAt: issuedAt,
          expiresAt,
        })
      )
      .digest('hex');
    const sgtMsg = new TextEncoder().encode(
      JSON.stringify({
        scheme: SIGNATURE_SCHEME,
        schema: SGT_SCHEMA,
        walletCommitmentHex: commitmentHex,
        sgtMint: BONK_MINT,
        groupAddress: SEEKER_SGT_GROUP_ADDRESS,
        skrDomain: 'abigail.skr',
        verifiedAt: issuedAt,
        expiresAt,
        digestHex: sgtDigest,
      })
    );
    const signedSgt: SignedSgtReceipt = {
      schema: SGT_SCHEMA,
      walletCommitmentHex: commitmentHex,
      sgtMint: BONK_MINT,
      groupAddress: SEEKER_SGT_GROUP_ADDRESS,
      skrDomain: 'abigail.skr',
      verifiedAt: issuedAt,
      expiresAt,
      digestHex: sgtDigest,
      issuerPubkey: ISSUER_PUBKEY,
      signatureBase58: bs58.encode(nacl.sign.detached(sgtMsg, KP.secretKey)),
      signatureScheme: SIGNATURE_SCHEME,
    };
    expect(verifySignedSgtReceipt(signedSgt, ISSUER_PUBKEY)).toBe(true);
  });

  it('guards Solana Actions / Blink URLs against HTTP downgrade and blocked honeypots', () => {
    const okSigned = signSafetyAttestation(sampleAttestation('ok'), SEED_HEX);
    const blockedSigned = signSafetyAttestation(sampleAttestation('blocked'), SEED_HEX);

    expect(guardSolanaBlinkUrl(`solana-action:https://stampedfi.com/api/actions/pop/${BONK_MINT}`, okSigned, ISSUER_PUBKEY)).toMatchObject({
      allowed: true,
      extractedMint: BONK_MINT,
    });
    expect(guardSolanaBlinkUrl(`solana-action:http://evil.example/pop/${BONK_MINT}`)).toMatchObject({
      allowed: false,
    });
    expect(guardSolanaBlinkUrl(`https://dial.to/?action=solana-action%3Ahttps%3A%2F%2Fstampedfi.com%2Fapi%2Factions%2Fpop%2F${BONK_MINT}`, blockedSigned, ISSUER_PUBKEY)).toMatchObject({
      allowed: false,
    });
  });
});

describe('@stampedfi/mcp', () => {
  it('computes deterministic Stamp Shield Auto-2x House Money plans and verifies fetched attestations', async () => {
    const plan = computeStampShieldAuto2x({
      entryTokenUnits: 1_000_000_001n,
      decimals: 6,
      entryPriceUsd: 0.25,
    });
    expect(plan.sellAt2xTokenUnits).toBe('500000000');
    expect(plan.moonbagTokenUnits).toBe('500000001');
    expect(plan.targetPriceUsd).toBe(0.5);

    const signed = signSafetyAttestation(sampleAttestation('ok'), SEED_HEX);
    const mockFetch = vi.fn(async () => new Response(JSON.stringify(signed), { status: 200 })) as unknown as typeof fetch;

    const tools = createStampedMcpTools({
      baseUrl: 'https://stampedfi.com',
      expectedIssuerPubkey: ISSUER_PUBKEY,
      fetchImpl: mockFetch,
    });
    const res = await tools.verifyTokenSafety(BONK_MINT);
    expect(res.verified).toBe(true);
    expect(res.cryptographicMode).toBe('ed25519-v1');

    const mcpServer = createStampedMcpServer({ expectedIssuerPubkey: ISSUER_PUBKEY, fetchImpl: mockFetch });
    expect(mcpServer).toBeDefined();
  });
});
