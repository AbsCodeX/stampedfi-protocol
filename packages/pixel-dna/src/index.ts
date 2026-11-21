/**
 * @stampedfi/pixel-dna — StampedFi Pixel-DNA Living Seal Engine (STP-1) by STAMPED Labs, Inc.
 *
 * Proprietary media-binding engine that turns any StampedFi conviction card (PNG/JPEG/WebP/MP4 frame)
 * into a cryptographically verifiable banknote:
 *
 * 1. Invisible 128-bit Spread-Spectrum Haar-Luminance Watermark tiled in 256×128 px macro-tiles
 *    (16 cols × 8 rows of 16×16 px macroblocks). Encodes:
 *      - 16-bit Magic Header ("SF" = 0x53, 0x46)
 *      - 48-bit Base62 `stampId` (lossless 8-char `stampedfi.com/s/<stampId>`)
 *      - 48-bit Ed25519 Signature Tag (`sigTagHex`, 12 hex chars)
 *      - 16-bit CRC-16-CCITT integrity check
 *    Designed to survive JPEG recompression (Q >= 65), X/iMessage/WhatsApp sharing, and QR cropping.
 *
 * 2. 64-bit Perceptual Difference Hash (`dHash`) + Hamming distance comparator for visual
 *    tamper / Photoshop detection against the canonical on-chain `CardGenomeV1`.
 */

const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const BASE62_MAP = new Map<string, bigint>([...BASE62].map((ch, idx) => [ch, BigInt(idx)]));

export const PIXEL_DNA_MAGIC_0 = 0x53; // 'S'
export const PIXEL_DNA_MAGIC_1 = 0x46; // 'F'
export const PIXEL_DNA_BYTES = 16;
export const PIXEL_DNA_BITS = 128;
export const MACRO_SIZE = 16;
export const SUB_SIZE = 8;
export const TILE_COLS = 16;
export const TILE_ROWS = 8;

export interface PixelDnaPayload {
  /** 8-character Base62 canonical short code (e.g. `k9X2mP4q`) */
  stampId: string;
  /** 12 lowercase hex chars (48 bits) derived from the Ed25519 signature */
  sigTagHex: string;
}

export interface PixelDnaExtraction {
  stampId: string;
  sigTagHex: string;
  /** Normalized extraction confidence in [0, 1] */
  confidence: number;
  /** Number of 16×16 macroblocks contributing to the decoded payload */
  blocksUsed: number;
  /** Pixel offset (ox, oy) and cyclic tile shift (dx, dy) where lock occurred */
  alignment: { ox: number; oy: number; dx: number; dy: number };
}

export interface EmbedOptions {
  /** Target differential luminance separation between diagonal 8×8 quadrants. Default 12 (imperceptible, Q65-survivable). */
  targetDiff?: number;
  /** Maximum per-pixel RGB shift applied during embedding. Default 10 (keeps PSNR > 40 dB). */
  maxPixelShift?: number;
}

/** Encode an 8-character Base62 string losslessly into 6 big-endian bytes (48 bits). */
export function encodeBase62Id48(stampId: string): Uint8Array {
  if (!/^[0-9A-Za-z]{8}$/.test(stampId)) throw new Error('stampId must be exactly 8 Base62 characters');
  let val = 0n;
  for (const ch of stampId) {
    val = val * 62n + (BASE62_MAP.get(ch) ?? 0n);
  }
  const out = new Uint8Array(6);
  for (let i = 5; i >= 0; i--) {
    out[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return out;
}

/** Decode 6 big-endian bytes (48 bits) back into an 8-character Base62 string, or null if out of range. */
export function decodeBase62Id48(bytes: Uint8Array): string | null {
  if (bytes.length !== 6) return null;
  let val = 0n;
  for (let i = 0; i < 6; i++) {
    val = (val << 8n) | BigInt(bytes[i]);
  }
  const maxVal = 62n ** 8n;
  if (val >= maxVal) return null;
  const chars = new Array<string>(8);
  for (let i = 7; i >= 0; i--) {
    chars[i] = BASE62[Number(val % 62n)];
    val /= 62n;
  }
  return chars.join('');
}

/** Standard CRC-16-CCITT (poly 0x1021, init 0xFFFF). */
export function crc16Ccitt(data: Uint8Array): number {
  let crc = 0xffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i] << 8;
    for (let b = 0; b < 8; b++) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

/** Pack PixelDnaPayload into 16 bytes (128 bits): [magic(2), stampId(6), sigTag(6), crc16(2)]. */
export function packPixelDnaBytes(payload: PixelDnaPayload): Uint8Array {
  if (!/^[0-9a-f]{12}$/i.test(payload.sigTagHex)) throw new Error('sigTagHex must be 12 hex characters (48 bits)');
  const out = new Uint8Array(PIXEL_DNA_BYTES);
  out[0] = PIXEL_DNA_MAGIC_0;
  out[1] = PIXEL_DNA_MAGIC_1;
  out.set(encodeBase62Id48(payload.stampId), 2);
  const tagHex = payload.sigTagHex.toLowerCase();
  for (let i = 0; i < 6; i++) {
    out[8 + i] = parseInt(tagHex.slice(i * 2, i * 2 + 2), 16);
  }
  const crc = crc16Ccitt(out.subarray(0, 14));
  out[14] = (crc >> 8) & 0xff;
  out[15] = crc & 0xff;
  return out;
}

/** Unpack and validate 16 bytes (128 bits) into PixelDnaPayload; returns null on magic or CRC mismatch. */
export function unpackPixelDnaBytes(bytes: Uint8Array): PixelDnaPayload | null {
  if (bytes.length !== PIXEL_DNA_BYTES) return null;
  if (bytes[0] !== PIXEL_DNA_MAGIC_0 || bytes[1] !== PIXEL_DNA_MAGIC_1) return null;
  const expected = crc16Ccitt(bytes.subarray(0, 14));
  const actual = (bytes[14] << 8) | bytes[15];
  if (expected !== actual) return null;
  const stampId = decodeBase62Id48(bytes.subarray(2, 8));
  if (!stampId) return null;
  let sigTagHex = '';
  for (let i = 8; i < 14; i++) sigTagHex += bytes[i].toString(16).padStart(2, '0');
  return { stampId, sigTagHex };
}

function bytesToBits(bytes: Uint8Array): Uint8Array {
  const bits = new Uint8Array(bytes.length * 8);
  for (let i = 0; i < bytes.length; i++) {
    for (let b = 0; b < 8; b++) {
      bits[i * 8 + b] = (bytes[i] >> (7 - b)) & 1;
    }
  }
  return bits;
}

function bitsToBytes(bits: Uint8Array): Uint8Array {
  const out = new Uint8Array(bits.length >> 3);
  for (let i = 0; i < out.length; i++) {
    let v = 0;
    for (let b = 0; b < 8; b++) v = (v << 1) | (bits[i * 8 + b] & 1);
    out[i] = v;
  }
  return out;
}

function clampByte(v: number): number {
  return v <= 0 ? 0 : v >= 255 ? 255 : Math.round(v);
}

/** Compute Rec.601 luminance of an RGBA pixel at offset `idx`. */
function lumaAt(rgba: Uint8Array, idx: number): number {
  return 0.299 * rgba[idx] + 0.587 * rgba[idx + 1] + 0.114 * rgba[idx + 2];
}

function quadrantMeanY(rgba: Uint8Array, width: number, x0: number, y0: number): number {
  let sum = 0;
  for (let y = y0; y < y0 + SUB_SIZE; y++) {
    let idx = (y * width + x0) * 4;
    for (let x = 0; x < SUB_SIZE; x++) {
      sum += lumaAt(rgba, idx);
      idx += 4;
    }
  }
  return sum / (SUB_SIZE * SUB_SIZE);
}

function shiftQuadrant(rgba: Uint8Array, width: number, x0: number, y0: number, delta: number): void {
  if (Math.abs(delta) < 0.05) return;
  for (let y = y0; y < y0 + SUB_SIZE; y++) {
    let idx = (y * width + x0) * 4;
    for (let x = 0; x < SUB_SIZE; x++) {
      rgba[idx] = clampByte(rgba[idx] + delta);
      rgba[idx + 1] = clampByte(rgba[idx + 1] + delta);
      rgba[idx + 2] = clampByte(rgba[idx + 2] + delta);
      idx += 4;
    }
  }
}

/**
 * Embeds the 128-bit Pixel-DNA Living Seal invisibly across an RGBA pixel buffer (returns a new buffer).
 * Operates on 16×16 macroblocks tiled across the entire canvas so cropping off a QR code or
 * re-saving as JPEG (quality >= 65) preserves full cryptographic recovery.
 */
export function embedPixelDna(
  rgba: Uint8Array,
  width: number,
  height: number,
  payload: PixelDnaPayload,
  opts: EmbedOptions = {}
): Uint8Array {
  if (rgba.length !== width * height * 4) throw new Error('rgba buffer length does not match width*height*4');
  const out = new Uint8Array(rgba);
  const packed = packPixelDnaBytes(payload);
  const bits = bytesToBits(packed);
  const targetDiff = opts.targetDiff ?? 12;
  const maxShift = opts.maxPixelShift ?? 10;

  const cols = Math.floor(width / MACRO_SIZE);
  const rows = Math.floor(height / MACRO_SIZE);

  for (let r = 0; r < rows; r++) {
    const y0 = r * MACRO_SIZE;
    for (let c = 0; c < cols; c++) {
      const x0 = c * MACRO_SIZE;
      const bitIndex = (r % TILE_ROWS) * TILE_COLS + (c % TILE_COLS);
      const bit = bits[bitIndex];

      const a = quadrantMeanY(out, width, x0, y0);
      const b = quadrantMeanY(out, width, x0 + SUB_SIZE, y0);
      const cMean = quadrantMeanY(out, width, x0, y0 + SUB_SIZE);
      const d = quadrantMeanY(out, width, x0 + SUB_SIZE, y0 + SUB_SIZE);
      // 2D Haar diagonal (A + D) - (B + C)
      const diff = (a + d) - (b + cMean);

      if (bit === 1 && diff < targetDiff) {
        const needed = Math.min(maxShift, (targetDiff - diff) / 4 + 1.5);
        shiftQuadrant(out, width, x0, y0, needed);
        shiftQuadrant(out, width, x0 + SUB_SIZE, y0 + SUB_SIZE, needed);
        shiftQuadrant(out, width, x0 + SUB_SIZE, y0, -needed);
        shiftQuadrant(out, width, x0, y0 + SUB_SIZE, -needed);
      } else if (bit === 0 && diff > -targetDiff) {
        const needed = Math.min(maxShift, (targetDiff + diff) / 4 + 1.5);
        shiftQuadrant(out, width, x0, y0, -needed);
        shiftQuadrant(out, width, x0 + SUB_SIZE, y0 + SUB_SIZE, -needed);
        shiftQuadrant(out, width, x0 + SUB_SIZE, y0, needed);
        shiftQuadrant(out, width, x0, y0 + SUB_SIZE, needed);
      }
    }
  }
  return out;
}

function tryExtractAtOffset(
  rgba: Uint8Array,
  width: number,
  height: number,
  ox: number,
  oy: number
): PixelDnaExtraction | null {
  const cols = Math.floor((width - ox) / MACRO_SIZE);
  const rows = Math.floor((height - oy) / MACRO_SIZE);
  if (cols < TILE_COLS || rows < TILE_ROWS) return null;

  const acc = new Float64Array(PIXEL_DNA_BITS);
  const counts = new Uint32Array(PIXEL_DNA_BITS);

  for (let r = 0; r < rows; r++) {
    const y0 = oy + r * MACRO_SIZE;
    const tr = r % TILE_ROWS;
    for (let c = 0; c < cols; c++) {
      const x0 = ox + c * MACRO_SIZE;
      const tc = c % TILE_COLS;
      const a = quadrantMeanY(rgba, width, x0, y0);
      const b = quadrantMeanY(rgba, width, x0 + SUB_SIZE, y0);
      const cMean = quadrantMeanY(rgba, width, x0, y0 + SUB_SIZE);
      const d = quadrantMeanY(rgba, width, x0 + SUB_SIZE, y0 + SUB_SIZE);
      const diff = (a + d) - (b + cMean);
      // Soft-clipped vote so high-contrast photo edges in one tile cannot overwhelm quiet tiles
      const vote = Math.max(-1, Math.min(1, diff / 10));
      const idx = tr * TILE_COLS + tc;
      acc[idx] += vote;
      counts[idx] += 1;
    }
  }

  const shiftedBits = new Uint8Array(PIXEL_DNA_BITS);
  // Check (0, 0) first for O(1) fast path on uncropped cards, then all 128 cyclic tile shifts for cropped cards
  for (let dy = 0; dy < TILE_ROWS; dy++) {
    for (let dx = 0; dx < TILE_COLS; dx++) {
      let absSum = 0;
      for (let tr = 0; tr < TILE_ROWS; tr++) {
        const sr = (tr + dy) % TILE_ROWS;
        for (let tc = 0; tc < TILE_COLS; tc++) {
          const sc = (tc + dx) % TILE_COLS;
          const srcIdx = sr * TILE_COLS + sc;
          const meanVote = counts[srcIdx] > 0 ? acc[srcIdx] / counts[srcIdx] : 0;
          shiftedBits[tr * TILE_COLS + tc] = meanVote >= 0 ? 1 : 0;
          absSum += Math.abs(meanVote);
        }
      }
      const decoded = unpackPixelDnaBytes(bitsToBytes(shiftedBits));
      if (decoded) {
        return {
          stampId: decoded.stampId,
          sigTagHex: decoded.sigTagHex,
          confidence: Math.min(1, Number((absSum / PIXEL_DNA_BITS).toFixed(3))),
          blocksUsed: cols * rows,
          alignment: { ox, oy, dx, dy },
        };
      }
    }
  }
  return null;
}

/**
 * Extracts and CRC-16 verifies a StampedFi Pixel-DNA Living Seal directly from raw RGBA pixels.
 * Searches unaligned pixel crops automatically (0, 4, 8, 12 px phase offsets + all 128 cyclic tile shifts).
 */
export function extractPixelDna(
  rgba: Uint8Array,
  width: number,
  height: number,
  opts: { deepCropSearch?: boolean } = {}
): PixelDnaExtraction | null {
  if (rgba.length !== width * height * 4) return null;
  // Fast path: aligned (0, 0)
  const fast = tryExtractAtOffset(rgba, width, height, 0, 0);
  if (fast) return fast;
  if (opts.deepCropSearch === false) return null;

  // Coarse phase search for arbitrary-pixel crops (step 4 -> covers +/-2px drift cleanly on 8×8 quadrants)
  const steps = [0, 4, 8, 12, 2, 6, 10, 14];
  for (const oy of steps) {
    for (const ox of steps) {
      if (ox === 0 && oy === 0) continue;
      const hit = tryExtractAtOffset(rgba, width, height, ox, oy);
      if (hit) return hit;
    }
  }
  return null;
}

/**
 * Computes a deterministic dual-axis 64-bit perceptual difference hash (`dHash`: 32 horizontal + 32 vertical bits)
 * as a 16-char lowercase hex string. Resilient to JPEG recompression and resizing while sensitive to local edits.
 */
export function computeDHashHex(rgba: Uint8Array, width: number, height: number): string {
  if (rgba.length !== width * height * 4 || width < 9 || height < 9) {
    throw new Error('Invalid image dimensions for dHash');
  }
  const grid = new Float64Array(9 * 9);
  for (let gy = 0; gy < 9; gy++) {
    const yStart = Math.floor((gy * height) / 9);
    const yEnd = Math.max(yStart + 1, Math.floor(((gy + 1) * height) / 9));
    for (let gx = 0; gx < 9; gx++) {
      const xStart = Math.floor((gx * width) / 9);
      const xEnd = Math.max(xStart + 1, Math.floor(((gx + 1) * width) / 9));
      let sum = 0;
      let n = 0;
      for (let y = yStart; y < yEnd; y++) {
        for (let x = xStart; x < xEnd; x++) {
          sum += lumaAt(rgba, (y * width + x) * 4);
          n++;
        }
      }
      grid[gy * 9 + gx] = sum / Math.max(1, n);
    }
  }
  const out = new Uint8Array(8);
  let bitPos = 0;
  // 32 horizontal gradient bits across 4 evenly spaced rows (0, 2, 5, 7)
  for (const gy of [0, 2, 5, 7]) {
    for (let gx = 0; gx < 8; gx++) {
      const bit = grid[gy * 9 + gx] > grid[gy * 9 + gx + 1] ? 1 : 0;
      out[bitPos >> 3] = (out[bitPos >> 3] << 1) | bit;
      bitPos++;
    }
  }
  // 32 vertical gradient bits across 4 evenly spaced columns (0, 2, 5, 7)
  for (const gx of [0, 2, 5, 7]) {
    for (let gy = 0; gy < 8; gy++) {
      const bit = grid[gy * 9 + gx] > grid[(gy + 1) * 9 + gx] ? 1 : 0;
      out[bitPos >> 3] = (out[bitPos >> 3] << 1) | bit;
      bitPos++;
    }
  }
  return Array.from(out, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Hamming bit distance between two 16-char hex perceptual hashes (0 = identical, 64 = inverse). */
export function hammingDistanceHex(a: string, b: string): number {
  if (!/^[0-9a-f]{16}$/i.test(a) || !/^[0-9a-f]{16}$/i.test(b)) return 64;
  let dist = 0;
  for (let i = 0; i < 16; i += 2) {
    let x = parseInt(a.slice(i, i + 2), 16) ^ parseInt(b.slice(i, i + 2), 16);
    while (x) {
      dist += x & 1;
      x >>= 1;
    }
  }
  return dist;
}
