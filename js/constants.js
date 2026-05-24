// ═══════════════════════════════════════════════════════════════════
// constants.js  —  All compile-time constants and shared mutable state
// ═══════════════════════════════════════════════════════════════════
"use strict";

// ── App version (single source of truth — referenced by settings.js, index.html) ──
const APP_VERSION = "1.21";

// ── Format constants ────────────────────────────────────────────────
const MAGIC   = "0018";
const VERSION = 18;
// V18 fixes the chunk-IV derivation (XOR with idx+1 instead of idx so
// chunk 0 is never left with the raw base IV).  V17 and all prior formats
// remain fully readable — the dispatcher in decrypt.js routes each file
// to the correct handler based on its own magic+version bytes.
const SUPPORTED_VERSIONS = [18, 17, 15, 14, 13];

// ── Argon2id defaults ───────────────────────────────────────────────
const ARGON2_TIME_DEFAULT         = 4;
const ARGON2_MEM_DEFAULT          = 131072;  // 128 MB
const ARGON2_HASH_LEN             = 32;
const ARGON2_PARALLEL_LOCAL       = Math.min(navigator.hardwareConcurrency || 2, 8);
const ARGON2_PARALLEL_POLICY_CAP  = 8;
const MIN_PARALLELISM             = 1;
const MAX_PARALLELISM             = 64;

// ── Chunk/file limits ───────────────────────────────────────────────
const MIN_CHUNK_SIZE  = 4096;
const MAX_CHUNK_SIZE  = 256 * 1024 * 1024;
const MAX_CHUNK_COUNT = 0x100000000;

// ── Header layout ───────────────────────────────────────────────────
const SALT_LEN           = 16;
const IV_LEN             = 12;
const META_IV_LEN        = 12;
const FIXED_HEADER_V17   = 52;
const CHUNK_INDEX_IV_OFFSET = 8;

// ── Watchdog ─────────────────────────────────────────────────────────
// How long a single chunk operation may run before the stall watchdog fires.
const STALL_TIMEOUT_MS = 15000;   // 15 s (was 60 s)

// ── Validation limits ───────────────────────────────────────────────
const MIN_PASSWORD_LEN = 8;
const MAX_META_BYTES   = 65536;
// No hard file-size cap — files are processed chunk-by-chunk; the only real
// limit is available disk space and browser address-space for the write stream.
// We keep the constant for the "large file" info banner threshold (2 GB).
const LARGE_FILE_THRESHOLD = 2 * 1024 * 1024 * 1024;
const MAX_QUEUE_SIZE   = 100;

// ── Bitflags & compression codes ────────────────────────────────────
const FLAG_META_ENCRYPTED    = 0x01;
const COMPRESSION_NONE       = 2;   // pre-compressed / passthrough — added in V17.1
const COMPRESSION_STANDARD   = 0;
const COMPRESSION_AGGRESSIVE = 1;

// ═══════════════════════════════════════════════════════════════════
// Shared mutable state  (mutated by queue.js, ui.js, crypto core)
// ═══════════════════════════════════════════════════════════════════

let queue     = [];
let cancelled = false;
let isRunning = false;
let abortController = null;
let isAdvancedMode  = false;
let keyfileData     = null;   // Uint8Array | null
let _metaModalResolve = null;
let dragSrcIndex    = null;
let currentFileOrder = "added";
let currentTheme    = "dark";

let settings = {
    // Simple settings
    nameMode            : "preserve",
    customName          : "",
    compression         : "standard",
    keepMeta            : true,
    encryptMeta         : true,
    chunkSize           : 4 * 1024 * 1024,
    decryptNameOverride : "",
    previewMeta         : false,
    // Advanced settings
    argon2Time          : ARGON2_TIME_DEFAULT,
    argon2Mem           : ARGON2_MEM_DEFAULT,
    argon2Parallel      : ARGON2_PARALLEL_LOCAL,
    deterministicMode   : false,
    manualSalt          : "",
    useKeyfile          : false,
    useAAD              : false,
    aadString           : "",
    containerFormat     : "binary",
    genChecksum         : false,
    lineEndingNorm      : false,
    processingMode      : "streaming",
    memLimitMB          : 512,
    maxThreads          : 4,
    batchMode           : "sequential",
    autoVerify          : false,
    dryRunMode          : false,
    verboseLog          : false,
    diagLog             : false,   // chunk-level diagnostic logging (advanced only)
    fileOrder           : "added",
    useStreamSaver      : true,
};

// ═══════════════════════════════════════════════════════════════════
// TSFError — typed error class used throughout all modules
// ═══════════════════════════════════════════════════════════════════

class TSFError extends Error {
    constructor(type, message) {
        super(message);
        this.type = type;
    }
}
