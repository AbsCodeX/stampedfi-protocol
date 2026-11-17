#!/usr/bin/env node
/**
 * @stampedfi/mcp — Official MIT Model Context Protocol Server for StampedFi (STAMPED Labs, Inc.)
 *
 * Equips AI coding and trading agents (Claude Desktop, Cursor, Antigravity, ElizaOS, SendAI) with:
 * 1. `stamped_verify_token_safety` — Offline Ed25519 + SHA-256 verification of `stamped-sas-v1` verdicts
 * 2. `stamped_get_icm_assets` — 24/7 Equities (Sunrise/xStocks), Kalshi Predictions, Yield (Lulo/Sanctum) & DePIN
 * 3. `stamped_get_verified_theses` — Solana `x402-v1` machine-payable signal feed ($0.01 USDC or free preview)
 * 4. `stamped_verify_holder_tier` — Offline verification of Zero-Dox `stamped-tier-v1` Whale/Shark/Dolphin/Shrimp proofs
 * 5. `stamped_compute_stamp_shield` — Deterministic BigInt Auto-2x House Money & StampScore (0-1000) calculator
 */
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { isAddress } from '@solana/kit';
import { z } from 'zod';
import {
  verifySafetyAttestationDigest,
  verifySignedSafetyAttestation,
  verifySignedTierReceipt,
  type SafetyAttestation,
  type SignedSafetyAttestation,
  type SignedTierReceipt,
} from '@stampedfi/sas-verifier';

export const DEFAULT_STAMPEDFI_ORIGIN = 'https://stampedfi.com';

export interface StampShieldPlan {
  entryTokenUnits: string;
  sellAt2xTokenUnits: string;
  moonbagTokenUnits: string;
  targetPriceUsd: number;
  expectedGrossReturnUsd: number;
}

export function computeStampShieldAuto2x(input: {
  entryTokenUnits: bigint;
  decimals: number;
  entryPriceUsd: number;
}): StampShieldPlan {
  if (input.entryTokenUnits < 2n) throw new Error('entryTokenUnits must be >= 2');
  if (!Number.isInteger(input.decimals) || input.decimals < 0 || input.decimals > 18) {
    throw new Error('decimals must be an integer in 0..18');
  }
  if (!Number.isFinite(input.entryPriceUsd) || input.entryPriceUsd <= 0) {
    throw new Error('entryPriceUsd must be positive');
  }
  const sellAt2x = input.entryTokenUnits / 2n;
  const moonbag = input.entryTokenUnits - sellAt2x;
  const targetPriceUsd = input.entryPriceUsd * 2;
  const scale = 10 ** input.decimals;
  const expectedGrossReturnUsd = (Number(sellAt2x) / scale) * targetPriceUsd;
  return {
    entryTokenUnits: input.entryTokenUnits.toString(),
    sellAt2xTokenUnits: sellAt2x.toString(),
    moonbagTokenUnits: moonbag.toString(),
    targetPriceUsd,
    expectedGrossReturnUsd,
  };
}

export interface StampedMcpOptions {
  baseUrl?: string;
  expectedIssuerPubkey?: string;
  fetchImpl?: typeof fetch;
}

export function createStampedMcpTools(opts: StampedMcpOptions = {}) {
  const baseUrl = (opts.baseUrl ?? process.env.STAMPEDFI_API_URL ?? DEFAULT_STAMPEDFI_ORIGIN).replace(/\/+$/, '');
  const expectedIssuer = opts.expectedIssuerPubkey ?? process.env.STAMPEDFI_ISSUER_PUBKEY;
  const fetchFn = opts.fetchImpl ?? fetch;

  return {
    async verifyTokenSafety(mint: string) {
      if (!isAddress(mint)) {
        throw new Error(`Invalid Solana mint address: ${mint}`);
      }
      const res = await fetchFn(`${baseUrl}/api/safety/attest/${mint}`, {
        headers: { accept: 'application/json' },
      });
      if (!res.ok) {
        throw new Error(`StampedFi safety endpoint returned HTTP ${res.status}`);
      }
      const payload = (await res.json()) as SafetyAttestation | SignedSafetyAttestation;
      const isSigned = 'signatureBase58' in payload;
      const verified = isSigned
        ? verifySignedSafetyAttestation(payload, expectedIssuer)
        : verifySafetyAttestationDigest(payload);

      return {
        verified,
        cryptographicMode: isSigned ? 'ed25519-v1' : 'sha256-digest',
        attestation: payload,
      };
    },

    async getIcmAssets(category: 'all' | 'equity' | 'prediction' | 'yield' | 'depin' = 'all') {
      const res = await fetchFn(`${baseUrl}/api/market/icm?category=${encodeURIComponent(category)}`, {
        headers: { accept: 'application/json' },
      });
      if (!res.ok) {
        throw new Error(`StampedFi ICM endpoint returned HTTP ${res.status}`);
      }
      return await res.json();
    },

    async getVerifiedTheses(params: { paymentProofSignature?: string; preview?: boolean } = {}) {
      const query = params.preview || !params.paymentProofSignature ? '?preview=1' : '';
      const headers: Record<string, string> = { accept: 'application/json' };
      if (params.paymentProofSignature) {
        headers['X-Payment-Proof'] = params.paymentProofSignature;
      }
      const res = await fetchFn(`${baseUrl}/api/agent/x402/seeker-feed${query}`, { headers });
      const body = await res.json();
      return { httpStatus: res.status, ...body };
    },

    verifyHolderTier(receipt: SignedTierReceipt, issuerPubkey?: string) {
      const valid = verifySignedTierReceipt(receipt, issuerPubkey ?? expectedIssuer);
      return {
        valid,
        tier: valid ? receipt.tier : null,
        tierLabel: valid ? receipt.tierLabel : null,
        minPositionUsd: valid ? receipt.minPositionUsd : null,
        seekerHumanVerified: valid ? receipt.seekerHumanVerified : false,
      };
    },
  };
}

export function createStampedMcpServer(opts: StampedMcpOptions = {}): McpServer {
  const tools = createStampedMcpTools(opts);
  const server = new McpServer({
    name: '@stampedfi/mcp',
    version: '0.1.0',
  });

  server.tool(
    'stamped_verify_token_safety',
    'Fetch and cryptographically verify StampedFi stamped-sas-v1 5-tier safety attestation for any Solana token mint.',
    { mint: z.string().min(32).max(44).describe('Solana SPL / Token-2022 mint address in Base58') },
    async ({ mint }) => {
      const out = await tools.verifyTokenSafety(mint);
      return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
    }
  );

  server.tool(
    'stamped_get_icm_assets',
    'List StampedFi Internet Capital Markets (ICM) assets: 24/7 tokenized equities (Sunrise $SPCX, xStocks), Kalshi predictions, Lulo/Sanctum yield, and DePIN.',
    { category: z.enum(['all', 'equity', 'prediction', 'yield', 'depin']).default('all') },
    async ({ category }) => {
      const out = await tools.getIcmAssets(category);
      return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
    }
  );

  server.tool(
    'stamped_get_verified_theses',
    'Query StampedFi Seeker Hardware-Human & high-StampScore theses over HTTP 402 (x402-v1 Solana Mainnet USDC or free preview).',
    {
      paymentProofSignature: z.string().optional().describe('Optional Solana Mainnet 0.01 USDC transfer signature'),
      preview: z.boolean().default(true).describe('Set true for free sample signals without on-chain USDC payment'),
    },
    async ({ paymentProofSignature, preview }) => {
      const out = await tools.getVerifiedTheses({ paymentProofSignature, preview });
      return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
    }
  );

  server.tool(
    'stamped_verify_holder_tier',
    'Offline Ed25519 verification of a Zero-Dox stamped-tier-v1 receipt (proving Shrimp/Dolphin/Shark/Whale conviction without wallet doxxing).',
    {
      receiptJson: z.string().describe('JSON string of SignedTierReceipt'),
      expectedIssuerPubkey: z.string().optional(),
    },
    async ({ receiptJson, expectedIssuerPubkey }) => {
      const parsed = JSON.parse(receiptJson) as SignedTierReceipt;
      const out = tools.verifyHolderTier(parsed, expectedIssuerPubkey);
      return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
    }
  );

  server.tool(
    'stamped_compute_stamp_shield',
    'Deterministic BigInt Stamp Shield (Auto-2x House Money) exit calculator: sells 50% at 2.0x to recover 100% principal while 50% moonbag rides free.',
    {
      entryTokenUnits: z.string().regex(/^\d+$/).describe('Raw integer token base units bought'),
      decimals: z.number().int().min(0).max(18),
      entryPriceUsd: z.number().positive(),
    },
    async ({ entryTokenUnits, decimals, entryPriceUsd }) => {
      const out = computeStampShieldAuto2x({
        entryTokenUnits: BigInt(entryTokenUnits),
        decimals,
        entryPriceUsd,
      });
      return { content: [{ type: 'text', text: JSON.stringify(out, null, 2) }] };
    }
  );

  return server;
}

const isDirectEntry = (() => {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();

if (isDirectEntry) {
  const server = createStampedMcpServer();
  const transport = new StdioServerTransport();
  server.connect(transport).catch((err) => {
    process.stderr.write(`[@stampedfi/mcp] Fatal startup error: ${String(err)}\n`);
    process.exit(1);
  });
}
