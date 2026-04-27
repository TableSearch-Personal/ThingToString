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

    const result = await argon2.hash({
        pass       : passInput,
        salt,
        time,
        mem,
        hashLen,
        parallelism: effective,
        type       : argon2.ArgonType.Argon2id
    });
    return crypto.subtle.importKey(
        "raw", result.hash, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
    );
}

// ── IV per-chunk derivation ───────────────────────────────────────────

/**
 * XOR the 32-bit counter at CHUNK_INDEX_IV_OFFSET into a copy of baseIV.
 * This gives each chunk a unique, deterministic IV derived from the base IV.
 */
function chunkIV(baseIV, idx) {
    const iv = new Uint8Array(baseIV);
    const dv = new DataView(iv.buffer);
    dv.setUint32(CHUNK_INDEX_IV_OFFSET, dv.getUint32(CHUNK_INDEX_IV_OFFSET) ^ idx);
    return iv;
}

// ── Compression helpers ───────────────────────────────────────────────

/**
 * Compress a chunk with optional line-ending normalisation.
 * @param {Uint8Array} data
 * @param {"standard"|"aggressive"} mode
 * @returns {Uint8Array}
 */
function compressChunk(data, mode) {
    if (settings.lineEndingNorm && mode !== "aggressive") {
        // Only normalise if the data looks like text (no null bytes in first 512 B)
        const sample = data.slice(0, 512);
        if (!sample.some(b => b === 0)) {
            let s = new TextDecoder().decode(data);
            s = s.replace(/\r\n/g, "\n");
            data = new TextEncoder().encode(s);
        }
    }
    return mode === "aggressive"
        ? pako.deflateRaw(data, { level: 9 })
        : pako.deflate(data,    { level: 6 });
}

/** Decompress a single chunk (throws TSFError on failure). */
function decompressChunk(data, mode) {
    try { return mode === "aggressive" ? pako.inflateRaw(data) : pako.inflate(data); }
    catch { throw new TSFError("corrupt", "Chunk decompression failed — file corrupted"); }
}

/** Decompress an entire payload (legacy V13/V14 full-buffer path). */
function decompressFull(data, mode) {
    try { return mode === "aggressive" ? pako.inflateRaw(data) : pako.inflate(data); }
    catch { throw new TSFError("corrupt", "Decompression failed — file corrupted"); }
}

// ── Metadata validation ───────────────────────────────────────────────

const ALLOWED_COMPRESSION = ["standard", "aggressive"];
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
            const handle   = await window.showSaveFilePicker({
                suggestedName,
                types: [{ description: "File", accept: { [mimeType]: [] } }]
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
            logV(`⚠ showSaveFilePicker unavailable (${e.message}) — using Blob fallback`, "warn");
        }
    }
    const parts = [];
    return {
        write    : async chunk => parts.push(new Uint8Array(chunk)),
        close    : async () => {
            const blob = new Blob(parts, { type: mimeType });
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
