// ═══════════════════════════════════════════════════════════════════
// crypto.js  —  Crypto primitives: key derivation (Argon2id + AES-GCM),
//               compression helpers, metadata validation, byte utilities,
//               SHA-256, Base64, and file-save stream helpers
// ═══════════════════════════════════════════════════════════════════
"use strict";

// ── Key derivation ───────────────────────────────────────────────────

/**
 * Derive an AES-GCM CryptoKey using Argon2id.
 * When a keyfile is loaded, it is HKDF-style mixed into the password first.
 *
 * @param {string}  password
 * @param {Uint8Array} salt
 * @param {number}  parallelism
 * @param {{time?: number, mem?: number}} [argon2Params]  – override defaults
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(password, salt, parallelism, argon2Params = {}) {
    const effective = Math.min(parallelism, ARGON2_PARALLEL_POLICY_CAP);
    if (effective !== parallelism)
        logV(`  ℹ Parallelism capped: ${parallelism} → ${effective} (local policy)`, "info");

    let passInput = password;
    if (settings.useKeyfile && keyfileData) {
        // Mix: SHA-256(password_bytes || 0x00 || keyfile_bytes)
        const pwBytes  = new TextEncoder().encode(password);
        const combined = new Uint8Array(pwBytes.length + 1 + keyfileData.length);
        combined.set(pwBytes);
        combined[pwBytes.length] = 0x00;
        combined.set(keyfileData, pwBytes.length + 1);
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", combined));
        passInput = Array.from(digest).map(b => b.toString(16).padStart(2, "0")).join("");
        logV("  ℹ Keyfile mixed into key material", "info");
    }

    const time    = argon2Params.time    || settings.argon2Time    || ARGON2_TIME_DEFAULT;
    const mem     = argon2Params.mem     || settings.argon2Mem     || ARGON2_MEM_DEFAULT;
    const hashLen = ARGON2_HASH_LEN;

    let result;
    try {
        result = await argon2.hash({
            pass       : passInput,
            salt,
            time,
            mem,
            hashLen,
            parallelism: effective,
            type       : argon2.ArgonType.Argon2id
        });
    } catch (e) {
        // Argon2 WASM can throw RuntimeError (abort) or CompileError when the
        // Content-Security-Policy blocks WebAssembly. Surface this clearly.
        const msg = e && e.message ? e.message : String(e);
        if (msg.includes("wasm") || msg.includes("WebAssembly") || msg.includes("CompileError") || msg.includes("RuntimeError")) {
            throw new TSFError("wasm",
                "Argon2 (WebAssembly) failed to initialise. " +
                "This is usually caused by a Content-Security-Policy that blocks WebAssembly. " +
                "Ensure 'wasm-unsafe-eval' is present in script-src. Details: " + msg);
        }
        throw new TSFError("crypto", "Key derivation failed: " + msg);
    }
    return crypto.subtle.importKey(
        "raw", result.hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
}

// ── IV per-chunk derivation ───────────────────────────────────────────

/**
 * V18+ IV derivation: XOR with (idx + 1).
 * Using a 1-based counter ensures chunk 0 is always modified, so the raw
 * base IV is never used as-is for any chunk — critical in deterministic
 * mode where the same base IV could appear across multiple files encrypted
 * with the same password+filename combination.
 */
function chunkIV_v18(baseIV, idx) {
    const iv = new Uint8Array(baseIV);
    const dv = new DataView(iv.buffer);
    dv.setUint32(CHUNK_INDEX_IV_OFFSET, dv.getUint32(CHUNK_INDEX_IV_OFFSET) ^ (idx + 1));
    return iv;
}

/**
 * V17 IV derivation (legacy): XOR with idx.
 * Chunk 0 is XOR'd with 0, leaving it equal to the raw base IV.
 * Preserved exactly as-is for decrypting existing V17 files.
 */
function chunkIV_v17(baseIV, idx) {
    const iv = new Uint8Array(baseIV);
    const dv = new DataView(iv.buffer);
    dv.setUint32(CHUNK_INDEX_IV_OFFSET, dv.getUint32(CHUNK_INDEX_IV_OFFSET) ^ idx);
    return iv;
}

/**
 * Version-aware dispatcher used by both encrypt.js and decrypt.js.
 * Encrypt always calls with the current VERSION (18), so new files use
 * the fixed derivation.  Decrypt passes the version read from the file
 * header so legacy files are handled correctly.
 *
 * @param {Uint8Array} baseIV
 * @param {number}     idx      0-based chunk index
 * @param {number}     version  format version read from the file header
 */
function chunkIV(baseIV, idx, version) {
    return version >= 18 ? chunkIV_v18(baseIV, idx) : chunkIV_v17(baseIV, idx);
}

// ── Binary-format magic bytes ─────────────────────────────────────────
// Formats whose first bytes identify them as binary — skip line-ending
// normalisation unconditionally for these, regardless of null-byte scan.
// ZIP local-file header: PK\x03\x04  (50 4B 03 04)
// ZIP central-dir:       PK\x01\x02  (50 4B 01 02)
// PNG:   89 50 4E 47
// JPEG:  FF D8
// PDF:   25 50 44 46  (%PDF)
// GIF:   47 49 46 38  (GIF8)
// GZIP:  1F 8B
// BZIP2: 42 5A 68     (BZh)
// 7-ZIP: 37 7A BC AF  (7z\xBC\xAF)
// RAR:   52 61 72 21  (Rar!)
// TAR (ustar offset 257): heuristic not cheap — rely on null-byte scan
// Ogg:   4F 67 67 53  (OggS)
// RIFF (WAV/AVI/WebP): 52 49 46 46
// ELF:   7F 45 4C 46
// Class: CA FE BA BE
const BINARY_MAGIC = [
    [0x50, 0x4B, 0x03, 0x04],  // ZIP local header
    [0x50, 0x4B, 0x05, 0x06],  // ZIP end-of-central-dir
    [0x50, 0x4B, 0x01, 0x02],  // ZIP central dir
    [0x89, 0x50, 0x4E, 0x47],  // PNG
    [0xFF, 0xD8],               // JPEG
    [0x25, 0x50, 0x44, 0x46],  // PDF
    [0x47, 0x49, 0x46, 0x38],  // GIF
    [0x1F, 0x8B],               // GZIP
    [0x42, 0x5A, 0x68],        // BZIP2
    [0x37, 0x7A, 0xBC, 0xAF],  // 7-ZIP
    [0x52, 0x61, 0x72, 0x21],  // RAR4
    [0x52, 0x61, 0x72, 0x1A],  // RAR5
    [0x4F, 0x67, 0x67, 0x53],  // OGG
    [0x52, 0x49, 0x46, 0x46],  // RIFF (WAV/AVI/WebP)
    [0x7F, 0x45, 0x4C, 0x46],  // ELF
    [0xCA, 0xFE, 0xBA, 0xBE],  // Java class
];

function _isBinaryMagic(data) {
    for (const magic of BINARY_MAGIC) {
        if (magic.every((b, i) => data[i] === b)) return true;
    }
    return false;
}

// ── Compression helpers ───────────────────────────────────────────────

// Already-compressed formats that deflate makes larger, not smaller.
// We detect these on the FIRST chunk (i===0) and store the decision for
// the rest of the chunks via a per-encrypt flag set in encryptFile().
// Note: this is a best-effort heuristic — the user can always override by
// choosing "no compression" manually. We never skip compression mid-stream.
const PRECOMPRESSED_MAGIC = [
    [0x50, 0x4B, 0x03, 0x04],  // ZIP
    [0x50, 0x4B, 0x05, 0x06],  // ZIP (empty)
    [0x1F, 0x8B],               // GZIP
    [0x42, 0x5A, 0x68],        // BZIP2
    [0x37, 0x7A, 0xBC, 0xAF],  // 7-ZIP
    [0x52, 0x61, 0x72, 0x21],  // RAR4
    [0x52, 0x61, 0x72, 0x1A],  // RAR5
    [0xFD, 0x37, 0x7A, 0x58],  // XZ
    [0xFF, 0xD8],               // JPEG
    [0x89, 0x50, 0x4E, 0x47],  // PNG
    [0x47, 0x49, 0x46, 0x38],  // GIF
    [0x57, 0x45, 0x42, 0x50],  // WEBP (after RIFF header, but close enough)
    [0x66, 0x74, 0x79, 0x70],  // MP4/M4A/MOV (ftyp box)
    [0x00, 0x00, 0x00, 0x18],  // MP4 variant
    [0x49, 0x44, 0x33],        // MP3 (ID3 tag)
    [0xFF, 0xFB],               // MP3 (no ID3)
    [0xFF, 0xF3],               // MP3
    [0xFF, 0xF2],               // MP3
    [0x4F, 0x67, 0x67, 0x53],  // OGG
    [0x66, 0x4C, 0x61, 0x43],  // FLAC
];

function _isPrecompressed(data) {
    for (const magic of PRECOMPRESSED_MAGIC) {
        if (magic.every((b, i) => data[i] === b)) return true;
    }
    return false;
}

/**
 * Compress a chunk with optional line-ending normalisation.
 * If mode is "none" (pre-compressed passthrough), returns data unchanged.
 * On the FIRST chunk of a file, auto-detects pre-compressed formats and
 * returns "none" as the effective mode so the caller can store it in the header.
 *
 * @param {Uint8Array} data
 * @param {"standard"|"aggressive"|"none"} mode
 * @param {boolean} isFirstChunk  – pass true for chunk 0 to enable auto-detection
 * @returns {{ compressed: Uint8Array, effectiveMode: string }}
 */
function compressChunk(data, mode, isFirstChunk = false) {
    // Auto-detect on first chunk: if already compressed, switch to passthrough
    if (isFirstChunk && mode !== "none" && _isPrecompressed(data)) {
        logV("  ℹ Pre-compressed format detected — storing without re-compression", "info");
        return { compressed: data, effectiveMode: "none" };
    }

    if (mode === "none") return { compressed: data, effectiveMode: "none" };

    if (settings.lineEndingNorm && mode !== "aggressive") {
        const isBinary = _isBinaryMagic(data) ||
            data.slice(0, 512).some(b => b === 0);
        if (!isBinary) {
            let s = new TextDecoder().decode(data);
            s = s.replace(/\r\n/g, "\n");
            data = new TextEncoder().encode(s);
        }
    }
    const compressed = mode === "aggressive"
        ? pako.deflateRaw(data, { level: 9 })
        : pako.deflate(data,    { level: 6 });
    return { compressed, effectiveMode: mode };
}

/** Decompress a single chunk (throws TSFError on failure). */
function decompressChunk(data, mode) {
    if (mode === "none") return data;
    try { return mode === "aggressive" ? pako.inflateRaw(data) : pako.inflate(data); }
    catch { throw new TSFError("corrupt", "Chunk decompression failed — file corrupted"); }
}

/** Decompress an entire payload (legacy V13/V14 full-buffer path). */
function decompressFull(data, mode) {
    try { return mode === "aggressive" ? pako.inflateRaw(data) : pako.inflate(data); }
    catch { throw new TSFError("corrupt", "Decompression failed — file corrupted"); }
}

// ── Metadata validation ───────────────────────────────────────────────

const ALLOWED_COMPRESSION = ["standard", "aggressive", "none"];
const ALLOWED_NAME_MODES  = ["preserve", "custom", "hidden", "encrypted"];
const ALLOWED_META_KEYS   = new Set(["originalName", "mimeType", "compression", "created", "nameMode"]);

/**
 * Strict schema validation for TSF metadata objects.
 * Throws TSFError("corrupt", …) on any violation.
 */
function validateMeta(meta) {
    if (typeof meta !== "object" || meta === null)
        throw new TSFError("corrupt", "Invalid metadata: expected an object");
    if (!ALLOWED_COMPRESSION.includes(meta.compression))
        throw new TSFError("corrupt", `Invalid compression in metadata: "${meta.compression}"`);
    if (meta.originalName !== undefined &&
        (typeof meta.originalName !== "string" || meta.originalName.length === 0))
        throw new TSFError("corrupt", "Invalid originalName in metadata");
    if (meta.mimeType !== undefined && typeof meta.mimeType !== "string")
        throw new TSFError("corrupt", "Invalid mimeType in metadata");
    if (meta.created !== undefined &&
        (typeof meta.created !== "number" || !isFinite(meta.created)))
        throw new TSFError("corrupt", "Invalid created timestamp in metadata");
    if (meta.nameMode !== undefined && !ALLOWED_NAME_MODES.includes(meta.nameMode))
        throw new TSFError("corrupt", `Invalid nameMode in metadata: "${meta.nameMode}"`);
    for (const k of Object.keys(meta)) {
        if (!ALLOWED_META_KEYS.has(k))
            throw new TSFError("corrupt", `Unexpected metadata field: "${k}"`);
    }
}

// ── Byte utilities ────────────────────────────────────────────────────

function uint32ToBytes(v) {
    const b = new ArrayBuffer(4);
    new DataView(b).setUint32(0, v >>> 0);
    return new Uint8Array(b);
}

function uint64ToBytes(v) {
    const b  = new ArrayBuffer(8);
    const dv = new DataView(b);
    dv.setUint32(0, Math.floor(v / 0x100000000));
    dv.setUint32(4, v >>> 0);
    return new Uint8Array(b);
}

/**
 * Read a 64-bit big-endian unsigned integer from a DataView.
 * Throws TSFError if the value exceeds Number.MAX_SAFE_INTEGER.
 */
function readUint64(dv, offset) {
    const hi = dv.getUint32(offset);
    const lo = dv.getUint32(offset + 4);
    const v  = hi * 0x100000000 + lo;
    if (!Number.isSafeInteger(v))
        throw new TSFError("corrupt",
            `Chunk count exceeds safe integer range (hi=${hi}, lo=${lo})`);
    return v;
}

/** Concatenate multiple Uint8Arrays into one. */
function concatArrays(arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out   = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
}

// ── SHA-256 helper ────────────────────────────────────────────────────

async function sha256hex(data) {
    const buf = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── Base64 encode ─────────────────────────────────────────────────────

/** Encode large Uint8Array to Base64 without stack-overflow risk. */
function toBase64(bytes) {
    let s = "";
    const chunk = 8192;
    for (let i = 0; i < bytes.length; i += chunk)
        s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    return btoa(s);
}

// ── File-save stream helpers ──────────────────────────────────────────

/**
 * Open a write stream using the File System Access API when available,
 * falling back to collecting parts in memory and triggering a download.
 *
 * @returns {{ write(chunk): Promise<void>, close(): Promise<void>, streaming: boolean }}
 */
async function openWriteStream(suggestedName, mimeType = "application/octet-stream") {
    if (window.showSaveFilePicker) {
        try {
            // Build a safe accept entry.
            // • We always include "application/octet-stream" as a fallback key so the
            //   dialog works even when the stored MIME is unusual (e.g. "application/x-zip-compressed").
            // • We derive a file-extension hint from the suggested filename so the OS
            //   filter shows the right type, rather than relying on the MIME string alone.
            const ext = suggestedName.includes(".")
                ? "." + suggestedName.split(".").pop().toLowerCase()
                : "";
            const acceptEntry = { "application/octet-stream": ext ? [ext] : [] };
            // Also add the real MIME if it is a known valid type (no 'x-' subtypes that
            // some browsers reject, and never an empty string).
            if (mimeType && !mimeType.startsWith("application/x-") &&
                mimeType !== "application/octet-stream") {
                acceptEntry[mimeType] = ext ? [ext] : [];
            }

            const handle   = await window.showSaveFilePicker({
                suggestedName,
                types: [{ description: "File", accept: acceptEntry }]
            });
            const writable = await handle.createWritable();
            return {
                write    : async chunk => writable.write(chunk),
                close    : async ()    => writable.close(),
                streaming: true
            };
        } catch (e) {
            if (e.name === "AbortError")
                throw new TSFError("cancelled", "Save dialog cancelled");
            // Any other error (bad MIME, permission denied, unsupported browser quirk)
            // — fall through to the Blob download path rather than crashing.
            logV(`⚠ showSaveFilePicker failed (${e.message}) — using Blob fallback`, "warn");
        }
    }
    const parts = [];
    return {
        write    : async chunk => parts.push(new Uint8Array(chunk)),
        close    : async () => {
            const blob = new Blob(parts, { type: "application/octet-stream" });
            download(blob, suggestedName);
        },
        streaming: false,
        getParts : () => parts
    };
}

/** Trigger a browser download for a Blob. */
function download(blob, name) {
    const url = URL.createObjectURL(blob);
    const a   = Object.assign(document.createElement("a"), { href: url, download: name });
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
}
