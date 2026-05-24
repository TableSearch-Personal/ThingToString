// ═══════════════════════════════════════════════════════════════════
// verify.js  —  True round-trip verification after encryption.
//
// Unlike the old autoVerify which reused live in-memory state from
// encryptFile() (same `aad` object, same `key`, same `ciphertext`
// variable — never touching disk), this module:
//
//   1. Receives the written .tsf File object (read back from disk)
//   2. Parses its header bytes from scratch
//   3. Reconstructs the AAD byte-for-byte the same way decrypt.js does
//   4. Re-derives the key from the password using the salt in the header
//   5. Decrypts every chunk (or a configurable sample) with that key+AAD
//   6. Decompresses and spot-checks the plaintext against the original
//   7. Reports exactly which layer failed and why
//
// This catches any bug that lives in the write-then-read path:
//   - Wrong AAD construction (the bug that existed in decrypt.js)
//   - Header byte-order or layout errors
//   - Truncated or misaligned ciphertext
//   - Compression codec mismatch
//   - IV derivation regressions
//   - Base64 encoding/decoding round-trip errors
// ═══════════════════════════════════════════════════════════════════
"use strict";

/**
 * Perform a true round-trip verification of a freshly-written .tsf file.
 *
 * Every step is isolated and labelled so the log shows exactly which
 * layer failed when something goes wrong.
 *
 * @param {File}   tsfFile    The .tsf (or .tsf.b64) File object to verify.
 *                            Must be the file AS WRITTEN — read back from disk,
 *                            not a copy of any in-memory buffer from encryptFile().
 * @param {string} password   The password used during encryption (NFC-normalised).
 * @param {File}   origFile   The original plaintext File, used for spot-check.
 * @param {object} [opts]
 * @param {number} [opts.chunkSampleSize=3]   How many chunks to fully verify.
 *                            Always includes chunk 0 and the last chunk.
 *                            Set to Infinity to verify every chunk (slow for large files).
 * @returns {Promise<boolean>}  true = all checks passed, false = at least one failed.
 */
async function trueVerifyFile(tsfFile, password, origFile, opts = {}) {
    const sampleSize = opts.chunkSampleSize ?? 3;
    const label = `[verify] ${escapeHtml(tsfFile.name)}`;
    let passed = true;

    function vlog(msg, level = "info") {
        log(`  ${label}: ${msg}`, level);
    }
    function fail(msg) {
        log(`  ${label}: ✗ ${msg}`, "error");
        passed = false;
    }
    function ok(msg) {
        log(`  ${label}: ✓ ${msg}`, "success");
    }

    vlog("── True round-trip verification starting ──", "info");

    // ── Step 0: Resolve Base64 container ────────────────────────────────
    // If the written file is .tsf.b64, decode it first — this exercises
    // the same decode path that decryptFile() uses.
    let resolvedFile = tsfFile;
    if (tsfFile.name.endsWith(".tsf.b64")) {
        vlog("Step 0: Decoding Base64 container…", "info");
        try {
            const rawText  = await tsfFile.text();
            const stripped = rawText.replace(/\s+/g, "");
            const binStr   = atob(stripped);
            const bytes    = new Uint8Array(binStr.length);
            for (let i = 0; i < binStr.length; i++) bytes[i] = binStr.charCodeAt(i);
            resolvedFile = new File(
                [bytes],
                tsfFile.name.replace(/\.b64$/, ""),
                { type: "application/octet-stream" }
            );
            ok(`Step 0: Base64 decoded — ${formatSize(tsfFile.size)} → ${formatSize(resolvedFile.size)}`);
        } catch (e) {
            fail(`Step 0: Base64 decode failed — ${e.message}`);
            return false; // can't continue without the binary
        }
    } else {
        vlog("Step 0: Binary container — no decode needed", "info");
    }

    // ── Step 1: Size sanity ──────────────────────────────────────────────
    vlog("Step 1: Checking file size…", "info");
    if (resolvedFile.size === 0) {
        fail("Step 1: File is empty (0 bytes) — nothing was written");
        return false;
    }
    if (resolvedFile.size < FIXED_HEADER_V17) {
        fail(`Step 1: File too small for any valid header (${resolvedFile.size} B < ${FIXED_HEADER_V17} B)`);
        return false;
    }
    ok(`Step 1: File size = ${formatSize(resolvedFile.size)}`);

    // ── Step 2: Parse magic + version ───────────────────────────────────
    vlog("Step 2: Parsing magic bytes and version…", "info");
    const peek = new Uint8Array(await resolvedFile.slice(0, 5).arrayBuffer());
    const magic   = new TextDecoder().decode(peek.slice(0, 4));
    const version = peek[4];
    if (magic !== "0018" || version !== 18) {
        fail(`Step 2: Expected magic="0018" version=18, got magic="${magic}" version=${version}`);
        return false;
    }
    ok(`Step 2: Magic="${magic}" version=${version}`);

    // ── Step 3: Parse full fixed header ─────────────────────────────────
    vlog("Step 3: Parsing fixed header…", "info");
    let flags, parallelism, salt, baseIV, chunkSize, chunkCount, compByte, metaLen;
    try {
        const fixedBuf = new Uint8Array(await resolvedFile.slice(0, FIXED_HEADER_V17).arrayBuffer());
        const dv = new DataView(fixedBuf.buffer);
        let off = 4; // already verified magic (4 B) + version (1 B handled below)
        off++;       // version
        flags       = fixedBuf[off++];
        parallelism = fixedBuf[off++];
        salt        = fixedBuf.slice(off, off + SALT_LEN);  off += SALT_LEN;
        baseIV      = fixedBuf.slice(off, off + IV_LEN);    off += IV_LEN;
        chunkSize   = dv.getUint32(off);                    off += 4;
        chunkCount  = readUint64(dv, off);                  off += 8;
        compByte    = fixedBuf[off++];
        metaLen     = dv.getUint32(off);                    off += 4;

        if (parallelism < MIN_PARALLELISM || parallelism > MAX_PARALLELISM)
            throw new Error(`Parallelism out of range: ${parallelism}`);
        if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE)
            throw new Error(`Chunk size out of range: ${chunkSize}`);
        if (chunkCount === 0 || chunkCount > MAX_CHUNK_COUNT)
            throw new Error(`Chunk count out of range: ${chunkCount}`);
        if (metaLen > MAX_META_BYTES)
            throw new Error(`Metadata length out of range: ${metaLen}`);
        if (compByte !== COMPRESSION_STANDARD && compByte !== COMPRESSION_AGGRESSIVE && compByte !== COMPRESSION_NONE)
            throw new Error(`Unknown compression byte: ${compByte}`);
    } catch (e) {
        fail(`Step 3: Fixed header invalid — ${e.message}`);
        return false;
    }
    const metaEncrypted   = (flags & FLAG_META_ENCRYPTED) !== 0;
    const compressionMode = compByte === COMPRESSION_AGGRESSIVE ? "aggressive"
                          : compByte === COMPRESSION_NONE       ? "none"
                          :                                       "standard";
    ok(`Step 3: chunkSize=${formatSize(chunkSize)} chunkCount=${chunkCount} compression=${compressionMode} metaEncrypted=${metaEncrypted} parallelism=${parallelism}`);

    // ── Step 4: Read plain metadata + custom AAD ─────────────────────────
    vlog("Step 4: Reading plain metadata and custom AAD…", "info");
    let fullFixedBuf;
    let totalFixedLen;
    try {
        const plainHeaderEnd = FIXED_HEADER_V17 + metaLen;
        const peekAAD = new Uint8Array(await resolvedFile.slice(0, plainHeaderEnd + 4).arrayBuffer());
        if (peekAAD.length < plainHeaderEnd + 4)
            throw new Error("File truncated before custom AAD length field");
        const customAADLen = new DataView(peekAAD.buffer).getUint32(plainHeaderEnd);
        if (customAADLen > MAX_META_BYTES)
            throw new Error(`Custom AAD length out of range: ${customAADLen}`);
        totalFixedLen  = plainHeaderEnd + 4 + customAADLen;
        fullFixedBuf   = new Uint8Array(await resolvedFile.slice(0, totalFixedLen).arrayBuffer());
        if (fullFixedBuf.length < totalFixedLen)
            throw new Error("File truncated inside custom AAD");
    } catch (e) {
        fail(`Step 4: Plain metadata / custom AAD read failed — ${e.message}`);
        return false;
    }
    ok(`Step 4: Fixed region = ${totalFixedLen} B (plain meta=${metaLen} B)`);

    // ── Step 5: Re-derive key from disk bytes ────────────────────────────
    // CRITICAL: use the salt read from the written file, not any in-memory
    // variable from encryptFile(). If the salt was not written correctly,
    // this step will produce a different key and chunk decryption will fail.
    vlog("Step 5: Re-deriving key from written salt (full Argon2id)…", "info");
    let key;
    try {
        key = await deriveKey(password, salt, parallelism, {
            time : settings.argon2Time,
            mem  : settings.argon2Mem,
        });
    } catch (e) {
        fail(`Step 5: Key derivation failed — ${e.message}`);
        return false;
    }
    ok("Step 5: Key derived from written salt");

    // ── Step 6: Parse + decrypt encrypted metadata blob ─────────────────
    // Also builds the encMetaBlob bytes needed to reconstruct fullAAD.
    vlog("Step 6: Parsing encrypted metadata blob…", "info");
    let fileOffset = totalFixedLen;
    let encMetaBlobBytes = new Uint8Array(0); // bytes of [metaIV + encMetaLen + encMeta]
    let meta = { compression: compressionMode };

    if (metaEncrypted) {
        try {
            const hdrBuf = new Uint8Array(
                await resolvedFile.slice(fileOffset, fileOffset + META_IV_LEN + 4).arrayBuffer());
            if (hdrBuf.length < META_IV_LEN + 4)
                throw new Error("File truncated — missing encrypted metadata header");

            const metaIV     = hdrBuf.slice(0, META_IV_LEN);
            const encMetaLen = new DataView(hdrBuf.buffer).getUint32(META_IV_LEN);
            if (encMetaLen > MAX_META_BYTES + 32)
                throw new Error(`Encrypted metadata length out of range: ${encMetaLen}`);

            const encMetaBuf = new Uint8Array(
                await resolvedFile.slice(fileOffset + META_IV_LEN + 4,
                                         fileOffset + META_IV_LEN + 4 + encMetaLen).arrayBuffer());
            if (encMetaBuf.length < encMetaLen)
                throw new Error("File truncated inside encrypted metadata body");

            // Decrypt metadata — its AAD is fullFixedBuf alone (same as encrypt.js)
            let metaPlain;
            try {
                metaPlain = new Uint8Array(await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: metaIV, additionalData: fullFixedBuf },
                    key, encMetaBuf
                ));
            } catch {
                fail("Step 6: Encrypted metadata authentication failed — " +
                     "wrong password, corrupt metadata blob, or header bytes were modified after encryption");
                return false;
            }

            try {
                meta = JSON.parse(new TextDecoder().decode(metaPlain));
            } catch {
                fail("Step 6: Metadata decrypted but JSON is invalid — encryption or write may have corrupted the metadata body");
                return false;
            }

            // Capture the raw on-disk bytes of the entire encMetaBlob so we
            // can include them in fullAAD, exactly as encrypt.js did.
            const blobLen    = META_IV_LEN + 4 + encMetaLen;
            encMetaBlobBytes = new Uint8Array(
                await resolvedFile.slice(fileOffset, fileOffset + blobLen).arrayBuffer());
            fileOffset += blobLen;

            ok(`Step 6: Metadata decrypted — originalName="${meta.originalName || "(none)"}" mime="${meta.mimeType || "(none)"}" compression="${meta.compression}"`);
        } catch (e) {
            if (!passed) return false; // already logged above
            fail(`Step 6: Encrypted metadata parse error — ${e.message}`);
            return false;
        }
    } else {
        ok("Step 6: No encrypted metadata blob (flag not set)");
    }

    // ── Step 7: Reconstruct fullAAD ──────────────────────────────────────
    // This is the exact operation that had the bug in decrypt.js:
    // fullAAD must be fixedHeader + encMetaBlob, not just fixedHeader.
    vlog("Step 7: Reconstructing AAD from written bytes…", "info");
    let fullAAD;
    try {
        fullAAD = encMetaBlobBytes.length > 0
            ? concatArrays([fullFixedBuf, encMetaBlobBytes])
            : fullFixedBuf;
    } catch (e) {
        fail(`Step 7: AAD construction failed — ${e.message}`);
        return false;
    }
    ok(`Step 7: AAD = ${fullAAD.length} B (fixedHeader=${totalFixedLen} B + encMetaBlob=${encMetaBlobBytes.length} B)`);

    // ── Step 8: Validate chunk region size ───────────────────────────────
    vlog("Step 8: Validating declared chunk count against file size…", "info");
    const minBodySize = fileOffset + Number(chunkCount) * (4 + 17); // 4 len + 16 tag + 1 byte min
    if (resolvedFile.size < minBodySize) {
        fail(`Step 8: File too small for ${chunkCount} chunk(s) — expected ≥ ${formatSize(minBodySize)}, got ${formatSize(resolvedFile.size)}`);
        return false;
    }
    ok(`Step 8: File large enough for ${chunkCount} chunk(s)`);

    // ── Step 9: Chunk decryption sample ─────────────────────────────────
    // Build the set of chunk indices to verify. Always includes 0 and last.
    // For large files, samples evenly from the middle too.
    vlog(`Step 9: Decrypting chunk sample (up to ${sampleSize === Infinity ? "all" : sampleSize} chunk(s))…`, "info");

    const indicesToCheck = new Set([0, Number(chunkCount) - 1]);
    if (sampleSize === Infinity) {
        for (let i = 0; i < Number(chunkCount); i++) indicesToCheck.add(i);
    } else if (sampleSize > 2) {
        const step = Math.max(1, Math.floor(Number(chunkCount) / (sampleSize - 1)));
        for (let i = 0; i < Number(chunkCount) && indicesToCheck.size < sampleSize; i += step)
            indicesToCheck.add(i);
    }

    // We need to walk the chunk list sequentially to find offsets, since
    // chunks are variable-length. We scan all chunks but only decrypt the
    // sampled ones.
    let chunkOffset = fileOffset;
    const chunkOffsets = []; // store (offset, cipherLen) for each chunk

    vlog(`Step 9a: Scanning all ${chunkCount} chunk length prefixes…`, "info");
    for (let i = 0; i < Number(chunkCount); i++) {
        const lenBuf = new Uint8Array(
            await resolvedFile.slice(chunkOffset, chunkOffset + 4).arrayBuffer());
        if (lenBuf.length < 4) {
            fail(`Step 9a: Chunk ${i}: unexpected EOF reading length prefix at offset ${chunkOffset}`);
            return false;
        }
        const cipherLen = new DataView(lenBuf.buffer).getUint32(0);
        if (cipherLen === 0 || cipherLen > chunkSize + 512) {
            // 512 = GCM tag (16 B) + generous compression overhead headroom
            fail(`Step 9a: Chunk ${i}: implausible ciphertext length ${cipherLen} — header likely corrupt or file truncated`);
            return false;
        }
        chunkOffsets.push({ off: chunkOffset + 4, len: cipherLen });
        chunkOffset += 4 + cipherLen;
    }

    // Check that total consumed bytes match file size exactly
    if (chunkOffset !== resolvedFile.size) {
        const delta = resolvedFile.size - chunkOffset;
        fail(`Step 9a: ${delta > 0 ? delta + " unexpected trailing byte(s)" : (-delta) + " byte(s) missing"} after last chunk — file size does not match declared structure`);
        passed = false; // don't return yet — still attempt chunk decryption
    } else {
        ok(`Step 9a: All ${chunkCount} length prefixes consistent — total bytes match file size exactly`);
    }

    vlog(`Step 9b: Decrypting ${indicesToCheck.size} sampled chunk(s)…`, "info");
    let chunksFailed = 0;
    let firstPlainChunk = null; // kept for plaintext spot-check

    for (const i of [...indicesToCheck].sort((a, b) => a - b)) {
        const { off, len } = chunkOffsets[i];
        const cipherBuf = new Uint8Array(
            await resolvedFile.slice(off, off + len).arrayBuffer());
        if (cipherBuf.length < len) {
            fail(`Step 9b: Chunk ${i}: file truncated — expected ${len} B, got ${cipherBuf.length} B`);
            chunksFailed++;
            continue;
        }

        const iv = chunkIV(baseIV, i, 18);
        let plain;
        try {
            plain = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv, additionalData: fullAAD },
                key, cipherBuf
            ));
        } catch {
            // Give a precise diagnosis depending on which chunk failed
            if (i === 0) {
                fail(`Step 9b: Chunk 0: AES-GCM authentication FAILED — ` +
                     `most likely cause: AAD mismatch (check header reconstruction) ` +
                     `or wrong key (wrong password / salt misread)`);
            } else {
                fail(`Step 9b: Chunk ${i}: AES-GCM authentication failed — ` +
                     `chunk may be truncated, reordered, or the IV derivation is wrong for this index`);
            }
            chunksFailed++;
            continue;
        }

        // Attempt decompression — catches compression codec mismatches
        let decompressed;
        try {
            decompressed = decompressChunk(plain, meta.compression);
        } catch (e) {
            fail(`Step 9b: Chunk ${i}: Decrypted OK but decompression failed — compression mode mismatch or corrupt compressed data. Error: ${e.message}`);
            chunksFailed++;
            continue;
        }

        if (i === 0) firstPlainChunk = decompressed;

        ok(`Step 9b: Chunk ${i}: OK (cipher=${formatSize(len)} → plain=${formatSize(decompressed.length)})`);
    }

    if (chunksFailed > 0) {
        fail(`Step 9b: ${chunksFailed} of ${indicesToCheck.size} sampled chunk(s) failed`);
        passed = false;
    }

    // ── Step 10: Plaintext spot-check ────────────────────────────────────
    // Compare the first chunk's decrypted bytes against the original file's
    // first chunk bytes. Catches key derivation bugs (wrong key → wrong plain)
    // and compression roundtrip bugs (decompressed to wrong bytes).
    if (origFile && firstPlainChunk !== null) {
        vlog("Step 10: Plaintext spot-check against original file (first chunk)…", "info");
        try {
            const origSliceLen = Math.min(chunkSize, origFile.size);
            const origBytes    = new Uint8Array(await origFile.slice(0, origSliceLen).arrayBuffer());

            if (firstPlainChunk.length !== origSliceLen) {
                fail(`Step 10: First chunk decompressed to ${firstPlainChunk.length} B but original first chunk is ${origSliceLen} B — size mismatch`);
            } else {
                // Compare byte-by-byte, report offset of first divergence
                let mismatchAt = -1;
                for (let b = 0; b < origSliceLen; b++) {
                    if (firstPlainChunk[b] !== origBytes[b]) { mismatchAt = b; break; }
                }
                if (mismatchAt >= 0) {
                    fail(`Step 10: Plaintext mismatch at byte offset ${mismatchAt} — decrypted 0x${firstPlainChunk[mismatchAt].toString(16).padStart(2,"0")} but original is 0x${origBytes[mismatchAt].toString(16).padStart(2,"0")}`);
                } else {
                    ok(`Step 10: First chunk plaintext matches original exactly (${formatSize(origSliceLen)})`);
                }
            }
        } catch (e) {
            fail(`Step 10: Plaintext spot-check error — ${e.message}`);
        }
    } else if (!origFile) {
        vlog("Step 10: Skipped (no original file reference available)", "info");
    }

    // ── Summary ──────────────────────────────────────────────────────────
    if (passed) {
        log(`  ${label}: ✓ All verification steps passed`, "success");
    } else {
        log(`  ${label}: ✗ Verification FAILED — see details above`, "error");
    }

    return passed;
}
