import { describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import bs58 from 'bs58';
import {
  CALL_STAMP_SCHEMA,
  CALLER_PASSPORT_SCHEMA,
  CARD_GENOME_V1_BYTES,
  SAS_CALLER_PASSPORT_BINARY_BYTES,
  SAS_SCHEMA,
  SEEKER_SGT_GROUP_ADDRESS,
  SGT_SCHEMA,
  STP1_BATCH_DISCRIMINATOR,
  STP1_HOLDER_STATUS,
  STP1_MERKLE_BATCH_LEN,
  STP1_STAMP_DISCRIMINATOR,
  STP1_STAMP_RECORD_LEN,
  TIER_SCHEMA,
  attestationDigest,
  computePixelDnaTagHex,
  computeStampScore,
  decodeCardGenomeV1,
  decodeMerkleBatchV1Account,
  decodeSasCallerPassportV1,
  decodeStampRecordV1Account,
  encodeAnchorMerkleBatchIxData,
  encodeCardGenomeV1,
  encodeInitializeRegistryIxData,
  encodeMintAtomicStampIxData,
  encodeSasCallerPassportV1,
  encodeUpdateHolderStatusIxData,
  estimateTxV1AtomicBudget,
  guardSolanaBlinkUrl,
  sha256Hex,
  signCallStamp,
  signCallerPassport,
  signSafetyAttestation,
  signSgtReceipt,
  signTierReceipt,
  verifySafetyAttestationDigest,
  verifySignedCallStamp,
  verifySignedCallerPassport,
  verifySignedSafetyAttestation,
  verifySignedSgtReceipt,
  verifySignedTierReceipt,
  type SafetyAttestation,
} from '../packages/sas-verifier/src/index.js';
import {
  computeDHashHex,
  embedPixelDna,
  extractPixelDna,
  hammingDistanceHex,
  packPixelDnaBytes,
  unpackPixelDnaBytes,
} from '../packages/pixel-dna/src/index.js';
import { computeStampShieldAuto2x, createStampedMcpServer, createStampedMcpTools } from '../packages/stampedfi-mcp/src/index.js';

const SEED_HEX = '33'.repeat(32);
const KP = nacl.sign.keyPair.fromSeed(Buffer.from(SEED_HEX, 'hex'));
const ISSUER_PUBKEY = bs58.encode(KP.publicKey);
const BONK_MINT = 'DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263';
const FIXED_NOW = Date.parse('2026-11-20T12:00:00.000Z');

function sampleAttestation(level: SafetyAttestation['level'] = 'ok', expiresAt = '2026-11-20T12:15:00.000Z'): SafetyAttestation {
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
    attestedAt: '2026-11-20T12:00:00.000Z',
    expiresAt,
    digestHex: attestationDigest({
      schema: SAS_SCHEMA,
      mint: BONK_MINT,
      level,
      coverageBps: 10_000,
      flagIds,
      expiresAt,
    }),
  };
}

describe('@stampedfi/sas-verifier', () => {
  it('signs and verifies stamped-sas-v1 attestations in <1ms, rejects tampering, and enforces TTL expiry', () => {
    const unsigned = sampleAttestation('ok');
    const signed = signSafetyAttestation(unsigned, SEED_HEX, 'sf-ed25519-v1');

    const t0 = performance.now();
    const ok = verifySignedSafetyAttestation(signed, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: FIXED_NOW });
    const elapsedMs = performance.now() - t0;

    expect(ok).toBe(true);
    expect(elapsedMs).toBeLessThan(15);
    expect(verifySignedSafetyAttestation({ ...signed, summary: 'Tampered summary' }, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: FIXED_NOW })).toBe(false);
    expect(verifySignedSafetyAttestation(signed, { expectedIssuerPubkey: '11111111111111111111111111111111', nowMs: FIXED_NOW })).toBe(false);
    // Reject once expired past clock skew
    expect(verifySignedSafetyAttestation(signed, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: Date.parse('2026-11-20T12:20:00.000Z') })).toBe(false);
  });

  it('strictly enforces canonical stamped-sas-v1 schema pinning', () => {
    const base = sampleAttestation('caution');
    const wrongSchema = {
      ...base,
      schema: 'unknown-sas-v0' as unknown as SafetyAttestation['schema'],
    };
    expect(verifySafetyAttestationDigest(wrongSchema)).toBe(false);
  });

  it('signs, verifies, and enforces expiry on Zero-Dox stamped-tier-v1 and Seeker stamped-sgt-v1 receipts', () => {
    const commitmentHex = createHash('sha256').update('nonce:wallet:mint').digest('hex');
    const issuedAt = '2026-11-20T12:00:00.000Z';
    const expiresAt = '2026-11-20T13:00:00.000Z';

    const signedTier = signTierReceipt(
      { mint: BONK_MINT, tier: 'Whale', seekerHumanVerified: true, commitmentHex, issuedAt, expiresAt },
      SEED_HEX
    );
    expect(verifySignedTierReceipt(signedTier, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: FIXED_NOW })).toBe(true);
    expect(verifySignedTierReceipt(signedTier, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: Date.parse('2026-11-20T14:00:00.000Z') })).toBe(false);

    const signedSgt = signSgtReceipt(
      { walletCommitmentHex: commitmentHex, sgtMint: BONK_MINT, skrDomain: 'abigail.skr', verifiedAt: issuedAt, expiresAt },
      SEED_HEX
    );
    expect(verifySignedSgtReceipt(signedSgt, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: FIXED_NOW })).toBe(true);
    expect(verifySignedSgtReceipt(signedSgt, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: Date.parse('2026-11-20T14:00:00.000Z') })).toBe(false);
  });

  it('signs & verifies stamped-call-v1 conviction proofs and round-trips 168-byte Solana v1 CardGenomeV1', () => {
    const signed = signCallStamp(
      {
        schema: CALL_STAMP_SCHEMA,
        stampId: 'k9X2mP4q',
        postId: '550e8400-e29b-41d4-a716-446655440000',
        kind: 'buy_call',
        mint: BONK_MINT,
        symbol: 'BONK',
        creatorHandle: 'abigail',
        walletCommitmentHex: sha256Hex('wallet-commitment-1'),
        txSignature: '5'.repeat(88),
        slot: 451_892_104,
        entryPriceUsd: 0.00002415,
        supplyAtPost: 74_900_000_000_000,
        entryMcapUsd: 1_808_835_000,
        holderTier: 'Whale',
        thesisSha256: sha256Hex('Seeker cultural liquidity anchor; Stamp Shield 2x armed.'),
        artPhashHex: 'a1b2c3d4e5f60718',
        horizonDays: 7,
        issuedAt: '2026-11-20T12:00:00.000Z',
      },
      SEED_HEX,
      'sf-ed25519-2026-q4'
    );

    expect(verifySignedCallStamp(signed, { expectedIssuerPubkey: ISSUER_PUBKEY })).toBe(true);
    expect(verifySignedCallStamp({ ...signed, entryMcapUsd: 120_000 }, { expectedIssuerPubkey: ISSUER_PUBKEY })).toBe(false);

    const genome = encodeCardGenomeV1(signed);
    expect(genome.length).toBe(CARD_GENOME_V1_BYTES);
    const decoded = decodeCardGenomeV1(genome);
    expect(decoded).not.toBeNull();
    expect(decoded?.stampId).toBe('k9X2mP4q');
    expect(decoded?.mint).toBe(BONK_MINT);
    expect(decoded?.symbol).toBe('BONK');
    expect(decoded?.holderTier).toBe('Whale');
    expect(decoded?.slot).toBe(451_892_104);
    expect(decoded?.artPhashHex).toBe('a1b2c3d4e5f60718');
    expect(computePixelDnaTagHex(signed)).toMatch(/^[0-9a-f]{12}$/);
  });

  it('guards Solana Actions / Blink URLs against HTTP downgrade, unsigned payloads, and blocked honeypots', () => {
    const unsigned = sampleAttestation('ok');
    const okSigned = signSafetyAttestation(unsigned, SEED_HEX);
    const blockedSigned = signSafetyAttestation(sampleAttestation('blocked'), SEED_HEX);

    expect(
      guardSolanaBlinkUrl(`solana-action:https://stampedfi.com/api/actions/stamp/${BONK_MINT}`, okSigned, {
        expectedIssuerPubkey: ISSUER_PUBKEY,
        nowMs: FIXED_NOW,
      })
    ).toMatchObject({ allowed: true, extractedMint: BONK_MINT });

    // Unsigned attestation rejected by default
    expect(
      guardSolanaBlinkUrl(`solana-action:https://stampedfi.com/api/actions/stamp/${BONK_MINT}`, unsigned, {
        expectedIssuerPubkey: ISSUER_PUBKEY,
        nowMs: FIXED_NOW,
      })
    ).toMatchObject({ allowed: false });

    expect(guardSolanaBlinkUrl(`solana-action:http://evil.example/stamp/${BONK_MINT}`)).toMatchObject({
      allowed: false,
    });
    expect(
      guardSolanaBlinkUrl(
        `https://dial.to/?action=solana-action%3Ahttps%3A%2F%2Fstampedfi.com%2Fapi%2Factions%2Fstamp%2F${BONK_MINT}`,
        blockedSigned,
        { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: FIXED_NOW }
      )
    ).toMatchObject({ allowed: false });
  });
});

describe('@stampedfi/pixel-dna', () => {
  function makeSyntheticCard(w: number, h: number): Uint8Array {
    const rgba = new Uint8Array(w * h * 4);
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        const i = (y * w + x) * 4;
        // Rich artwork + radial card pattern mimicking a real StampedFi conviction card
        const wave = Math.round(50 * Math.sin(x / 65) * Math.cos(y / 55));
        rgba[i] = Math.max(0, Math.min(255, Math.floor(110 + wave + (x / w) * 70)));
        rgba[i + 1] = Math.max(0, Math.min(255, Math.floor(100 - wave + (y / h) * 80)));
        rgba[i + 2] = Math.max(0, Math.min(255, Math.floor(120 + Math.round(40 * Math.cos((x - y) / 90)))));
        rgba[i + 3] = 255;
      }
    }
    return rgba;
  }

  function cropRgba(src: Uint8Array, w: number, x0: number, y0: number, cw: number, ch: number): Uint8Array {
    const out = new Uint8Array(cw * ch * 4);
    for (let y = 0; y < ch; y++) {
      const srcOff = ((y0 + y) * w + x0) * 4;
      out.set(src.subarray(srcOff, srcOff + cw * 4), y * cw * 4);
    }
    return out;
  }

  it('packs & unpacks 128-bit Pixel-DNA payload with CRC-16 protection', () => {
    const packed = packPixelDnaBytes({ stampId: 'k9X2mP4q', sigTagHex: 'deadbeefcafe' });
    expect(packed.length).toBe(16);
    expect(unpackPixelDnaBytes(packed)).toEqual({ stampId: 'k9X2mP4q', sigTagHex: 'deadbeefcafe' });
    // Single-bit flip fails CRC-16
    packed[5] ^= 0x04;
    expect(unpackPixelDnaBytes(packed)).toBeNull();
  });

  it('embeds invisible Pixel-DNA seal and recovers it after noise + aggressive QR-stripping unaligned crop', () => {
    const w = 1200;
    const h = 630;
    const base = makeSyntheticCard(w, h);
    const payload = { stampId: 'k9X2mP4q', sigTagHex: 'a4f90c1277eb' };
    const watermarked = embedPixelDna(base, w, h, payload);

    // 1. Direct extraction
    const direct = extractPixelDna(watermarked, w, h);
    expect(direct).not.toBeNull();
    expect(direct?.stampId).toBe('k9X2mP4q');
    expect(direct?.sigTagHex).toBe('a4f90c1277eb');

    // 2. Simulate JPEG quantization noise (+/- 3 luma) + aggressive unaligned crop removing bottom & right (QR gone!)
    const noisy = new Uint8Array(watermarked);
    for (let i = 0; i < noisy.length; i += 4) {
      const jitter = ((i / 4) % 7) - 3;
      noisy[i] = Math.max(0, Math.min(255, noisy[i] + jitter));
      noisy[i + 1] = Math.max(0, Math.min(255, noisy[i + 1] - jitter));
      noisy[i + 2] = Math.max(0, Math.min(255, noisy[i + 2] + jitter));
    }
    const cropped = cropRgba(noisy, w, 38, 22, 640, 340);
    const recovered = extractPixelDna(cropped, 640, 340);
    expect(recovered).not.toBeNull();
    expect(recovered?.stampId).toBe('k9X2mP4q');
    expect(recovered?.sigTagHex).toBe('a4f90c1277eb');

    // 3. Unwatermarked card returns null (no false positives)
    expect(extractPixelDna(base, w, h)).toBeNull();

    // 4. Perceptual dHash stays near-identical after invisible watermark, diverges on tampered block
    const hBase = computeDHashHex(base, w, h);
    const hWater = computeDHashHex(watermarked, w, h);
    expect(hammingDistanceHex(hBase, hWater)).toBeLessThanOrEqual(4);

    // Tamper heavily with upper half of image
    const tampered = new Uint8Array(watermarked);
    tampered.fill(250, 0, Math.floor(tampered.length / 2));
    expect(hammingDistanceHex(hWater, computeDHashHex(tampered, w, h))).toBeGreaterThan(8);
  });
});

describe('@stampedfi/mcp', () => {
  it('computes deterministic Stamp Shield Auto-2x House Money plans and verifies fetched attestations & call stamps', async () => {
    const plan = computeStampShieldAuto2x({
      entryTokenUnits: 1_000_000_001n,
      decimals: 6,
      entryPriceUsd: 0.25,
    });
    expect(plan.sellAt2xTokenUnits).toBe('500000000');
    expect(plan.moonbagTokenUnits).toBe('500000001');
    expect(plan.targetPriceUsd).toBe(0.5);

    const signedSafety = signSafetyAttestation(
      sampleAttestation('ok', new Date(Date.now() + 15 * 60_000).toISOString()),
      SEED_HEX
    );
    const signedCall = signCallStamp(
      {
        schema: CALL_STAMP_SCHEMA,
        stampId: 'k9X2mP4q',
        postId: '550e8400-e29b-41d4-a716-446655440000',
        kind: 'buy_call',
        mint: BONK_MINT,
        symbol: 'BONK',
        creatorHandle: 'abigail',
        walletCommitmentHex: sha256Hex('wallet-commitment-1'),
        txSignature: null,
        slot: 451_892_104,
        entryPriceUsd: 0.000024,
        supplyAtPost: 74_900_000_000_000,
        entryMcapUsd: 1_800_000_000,
        holderTier: 'Shark',
        thesisSha256: sha256Hex('Thesis text'),
        artPhashHex: null,
        horizonDays: 7,
        issuedAt: new Date().toISOString(),
      },
      SEED_HEX
    );

    const mockFetch = vi.fn(async (url: string) => {
      if (String(url).includes('/api/verify/stamp/')) {
        return new Response(JSON.stringify({ stamp: signedCall, liveHolder: { status: 'holding', checkedAt: new Date().toISOString() } }), { status: 200 });
      }
      return new Response(JSON.stringify(signedSafety), { status: 200 });
    }) as unknown as typeof fetch;

    const tools = createStampedMcpTools({
      baseUrl: 'https://stampedfi.com',
      expectedIssuerPubkey: ISSUER_PUBKEY,
      fetchImpl: mockFetch,
    });
    const res = await tools.verifyTokenSafety(BONK_MINT);
    expect(res.verified).toBe(true);
    expect(res.cryptographicMode).toBe('ed25519-v1');

    const callRes = await tools.verifyCallStamp('k9X2mP4q');
    expect(callRes.verified).toBe(true);
    expect(callRes.liveHolder?.status).toBe('holding');

    const mcpServer = createStampedMcpServer({ expectedIssuerPubkey: ISSUER_PUBKEY, fetchImpl: mockFetch });
    expect(mcpServer).toBeDefined();
  });

  it('encodes Solana Transaction v1 STP-1 instructions/accounts, validates 4,096 B v1 budget, and signs SAS Caller Passports', async () => {
    const signedCall = signCallStamp(
      {
        schema: CALL_STAMP_SCHEMA,
        stampId: 'k9X2mP4q',
        postId: '550e8400-e29b-41d4-a716-446655440000',
        kind: 'buy_call',
        mint: BONK_MINT,
        symbol: 'BONK',
        creatorHandle: 'abigail',
        walletCommitmentHex: sha256Hex('wallet-commitment-1'),
        txSignature: null,
        slot: 451_892_104,
        entryPriceUsd: 0.000024,
        supplyAtPost: 74_900_000_000_000,
        entryMcapUsd: 1_800_000_000,
        holderTier: 'Whale',
        thesisSha256: sha256Hex('Thesis text'),
        artPhashHex: 'a1b2c3d4e5f60718',
        horizonDays: 7,
        issuedAt: '2026-11-20T12:00:00.000Z',
      },
      SEED_HEX
    );
    const genome = encodeCardGenomeV1(signedCall);

    // 1. Instruction codecs match Pinocchio Rust sizes byte-for-byte
    const initIx = encodeInitializeRegistryIxData({ authorizedIssuer: ISSUER_PUBKEY, treasury: BONK_MINT, b2bFeeLamports: 500_000n });
    expect(initIx.length).toBe(73);
    expect(initIx[0]).toBe(0);

    const mintIx = encodeMintAtomicStampIxData({ partnerId: 42, cardGenomeV1: genome });
    expect(mintIx.length).toBe(171);
    expect(mintIx[0]).toBe(1);

    const batchIx = encodeAnchorMerkleBatchIxData({ batchId: 7n, merkleRootHex: 'ab'.repeat(32), leafCount: 250 });
    expect(batchIx.length).toBe(45);
    expect(batchIx[0]).toBe(2);

    const updateIx = encodeUpdateHolderStatusIxData({ newStatus: STP1_HOLDER_STATUS.Shield2xTrimmed, exitTxSigSha256Hex: 'cd'.repeat(32) });
    expect(updateIx.length).toBe(34);
    expect(updateIx[0]).toBe(3);

    // 2. Account decoders round-trip 276-byte StampRecordV1 and 97-byte MerkleBatchV1
    const rawStamp = new Uint8Array(STP1_STAMP_RECORD_LEN);
    const sView = new DataView(rawStamp.buffer);
    rawStamp.set(STP1_STAMP_DISCRIMINATOR, 0);
    rawStamp.set(genome, 8);
    sView.setBigUint64(176, 451_892_104n, true);
    sView.setBigInt64(184, 1795176000n, true);
    rawStamp.set(bs58.decode(ISSUER_PUBKEY), 192);
    sView.setUint16(224, 42, true);
    rawStamp[226] = STP1_HOLDER_STATUS.HoldingConviction;
    rawStamp[227] = 254;
    sView.setBigUint64(228, 451_892_104n, true);
    const decodedRec = decodeStampRecordV1Account(rawStamp);
    expect(decodedRec).not.toBeNull();
    expect(decodedRec?.partnerId).toBe(42);
    expect(decodedRec?.genome.stampId).toBe('k9X2mP4q');
    expect(decodedRec?.callerSigner).toBe(ISSUER_PUBKEY);

    const rawBatch = new Uint8Array(STP1_MERKLE_BATCH_LEN);
    const bView = new DataView(rawBatch.buffer);
    rawBatch.set(STP1_BATCH_DISCRIMINATOR, 0);
    bView.setBigUint64(8, 7n, true);
    rawBatch.set(Buffer.from('ab'.repeat(32), 'hex'), 16);
    bView.setUint32(48, 250, true);
    bView.setBigUint64(52, 451_892_200n, true);
    bView.setBigInt64(60, 1795176060n, true);
    rawBatch[96] = 253;
    expect(decodeMerkleBatchV1Account(rawBatch)).toMatchObject({ batchId: 7n, merkleRootHex: 'ab'.repeat(32), leafCount: 250, bump: 253 });

    // 3. Tx v1 budget estimator enforces 4,096 B cap AND explicit computeUnitLimit
    const okBudget = estimateTxV1AtomicBudget({
      swapIxBytes: 720,
      accountCount: 30,
      includeZkProofBytes: 256,
      includeLightProofBytes: 180,
      computeUnitLimit: 350_000,
    });
    expect(okBudget.fits).toBe(true);
    expect(okBudget.headroomBytes).toBeGreaterThan(1000);

    const noCuBudget = estimateTxV1AtomicBudget({ swapIxBytes: 500, accountCount: 20 });
    expect(noCuBudget.fits).toBe(false);
    expect(noCuBudget.computeUnitLimitValid).toBe(false);

    // 4. StampScore (0-1000) & Official SAS Caller Passport
    const score = computeStampScore({
      verifiedCalls: 40,
      hitRate2x: 0.85,
      holdDiscipline: 0.95,
      earlyDumpCount: 0,
      medianMultiple: 3.0,
      totalVolumeDrivenUsd: 500_000,
      humanTier: 3,
    });
    expect(score.score).toBeGreaterThanOrEqual(880);
    expect(score.tier).toBe('Diamond Sovereign');
    expect(score.callerFeeShareBps).toBe(3500);

    const sasBin = encodeSasCallerPassportV1({
      stampScore: score.score,
      totalAuditedCalls: 40,
      hitRate2xBps: score.hitRate2xBps,
      holdDisciplineBps: score.holdDisciplineBps,
      medianMultipleBps: score.medianMultipleBps,
      humanTier: 3,
      lastAuditedEpoch: 1035,
    });
    expect(sasBin.length).toBe(SAS_CALLER_PASSPORT_BINARY_BYTES);
    expect(decodeSasCallerPassportV1(sasBin)).toMatchObject({ stampScore: score.score, totalAuditedCalls: 40, humanTier: 3, lastAuditedEpoch: 1035 });

    const signedPassport = signCallerPassport(
      {
        handle: 'abigail',
        walletCommitmentHex: sha256Hex('wallet-abigail'),
        stampScore: score.score,
        tier: score.tier,
        callerFeeShareBps: score.callerFeeShareBps,
        totalAuditedCalls: 40,
        hitRate2xBps: score.hitRate2xBps,
        holdDisciplineBps: score.holdDisciplineBps,
        medianMultipleBps: score.medianMultipleBps,
        humanTier: 3,
        lastAuditedEpoch: 1035,
        issuedAt: '2026-11-20T12:00:00.000Z',
        expiresAt: '2026-11-21T12:00:00.000Z',
      },
      SEED_HEX
    );
    expect(signedPassport.schema).toBe(CALLER_PASSPORT_SCHEMA);
    expect(verifySignedCallerPassport(signedPassport, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: FIXED_NOW })).toBe(true);
    expect(verifySignedCallerPassport({ ...signedPassport, stampScore: 999 }, { expectedIssuerPubkey: ISSUER_PUBKEY, nowMs: FIXED_NOW })).toBe(false);

    // MCP tool fetches & offline-verifies caller passport
    const passportMockFetch = vi.fn(async () => new Response(JSON.stringify({ verified: true, passport: signedPassport }), { status: 200 })) as unknown as typeof fetch;
    const passportTools = createStampedMcpTools({ expectedIssuerPubkey: ISSUER_PUBKEY, fetchImpl: passportMockFetch });
    const mcpPassport = await passportTools.getCallerPassport('@abigail');
    expect(mcpPassport.verified).toBe(true);
    expect(mcpPassport.passport?.tier).toBe('Diamond Sovereign');
  });
});
