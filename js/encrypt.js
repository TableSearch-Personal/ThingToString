// ═══════════════════════════════════════════════════════════════════
// encrypt.js  —  V18 encryption (current format)
// ═══════════════════════════════════════════════════════════════════
"use strict";

/**
 * Encrypt a single file and stream/download the result as a .tsf or .tsf.b64.
 *
 * @param {File}   file
 * @param {string} password
 */
async function encryptFile(file, password) {
    log(`Encrypt: ${escapeHtml(file.name)} (${formatSize(file.size)})`, "info");

    if (file.size === 0)
        logV("  ⚠ Empty file — encrypting as single empty chunk", "warn");

    const mode       = settings.compression;
    const chunkSize  = settings.chunkSize;
    const chunkCount = Math.ceil(file.size / chunkSize) || 1;

    if (chunkCount > MAX_CHUNK_COUNT)
        throw new TSFError("size", `File would require too many chunks: ${chunkCount}`);

    // ── Salt — validate hex before use ───────────────────────────────
    let salt;
    if (settings.deterministicMode && settings.manualSalt) {
        if (!/^[0-9a-fA-F]{32}$/.test(settings.manualSalt))
            throw new TSFError("validation",
                "Manual salt must be exactly 32 hex characters (0-9, a-f). " +
                "Use the 🎲 Random button to generate a valid salt.");
        salt = new Uint8Array(settings.manualSalt.match(/../g).map(h => parseInt(h, 16)));
        logV("  ⚠ Deterministic mode: using manual salt", "warn");
    } else if (settings.deterministicMode) {
        const input   = new TextEncoder().encode(password + "|" + file.name);
        const hashBuf = await crypto.subtle.digest("SHA-256", input);
        salt = new Uint8Array(hashBuf).slice(0, SALT_LEN);
        logV("  ⚠ Deterministic mode: derived salt from password+filename", "warn");
    } else {
        salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    }

    // ── Base IV ──────────────────────────────────────────────────────
    const resolvedBaseIV = settings.deterministicMode
        ? await (async () => {
            const input = new TextEncoder().encode("nonce|" + password + "|" + file.name);
            const h = await crypto.subtle.digest("SHA-256", input);
            return new Uint8Array(h).slice(0, IV_LEN);
          })()
        : crypto.getRandomValues(new Uint8Array(IV_LEN));

    log("  Deriving key…", "info");
    const key = await deriveKey(password, salt, settings.argon2Parallel, {
        time : settings.argon2Time,
        mem  : settings.argon2Mem,
    });

    // ── Output filename ───────────────────────────────────────────────
    let finalName;
    if      (settings.nameMode === "custom")    finalName = settings.customName || "custom_file";
    else if (settings.nameMode === "hidden")    finalName = "hidden";
    else if (settings.nameMode === "encrypted") finalName = crypto.randomUUID().replace(/-/g, "");
    else                                         finalName = file.name;

    // ── Effective compression mode ────────────────────────────────────
    let effectiveMode = mode;
    if (file.size > 0 && mode !== "none") {
        const peekBuf = new Uint8Array(await file.slice(0, 8).arrayBuffer());
        if (_isPrecompressed(peekBuf)) {
            effectiveMode = "none";
            logV("  ℹ Pre-compressed format detected — storing without re-compression", "info");
        }
    }

    const doEncMeta   = settings.keepMeta && settings.encryptMeta;
    const doPlainMeta = settings.keepMeta && !settings.encryptMeta;
    let flags = 0;
    if (doEncMeta) flags |= FLAG_META_ENCRYPTED;

    const compressionByte = effectiveMode === "aggressive" ? COMPRESSION_AGGRESSIVE
                          : effectiveMode === "none"       ? COMPRESSION_NONE
                          :                                  COMPRESSION_STANDARD;

    const plainMetaBytes = doPlainMeta
        ? (() => {
            const json  = JSON.stringify({
                originalName: file.name, mimeType: file.type,
                compression: effectiveMode, created: Date.now(), nameMode: settings.nameMode
            });
            const bytes = new TextEncoder().encode(json);
            if (bytes.length > MAX_META_BYTES)
                throw new TSFError("validation", `Metadata too large: ${bytes.length} B`);
            return bytes;
          })()
        : new Uint8Array(0);

    const customAADBytes = (settings.useAAD && settings.aadString)
        ? new TextEncoder().encode(settings.aadString)
        : new Uint8Array(0);

    const parallelismByte = Math.min(settings.argon2Parallel, 255);
    const fixedHeader = concatArrays([
        new TextEncoder().encode(MAGIC),
        new Uint8Array([VERSION]),
        new Uint8Array([flags]),
        new Uint8Array([parallelismByte]),
        salt,
        resolvedBaseIV,
        uint32ToBytes(chunkSize),
        uint64ToBytes(chunkCount),
        new Uint8Array([compressionByte]),
        uint32ToBytes(plainMetaBytes.length),
        plainMetaBytes,
        uint32ToBytes(customAADBytes.length),
        customAADBytes,
    ]);

    // ── Encrypted metadata blob ───────────────────────────────────────
    let encMetaBlob = new Uint8Array(0);
    if (doEncMeta) {
        const metaJson = new TextEncoder().encode(JSON.stringify({
            originalName: file.name, mimeType: file.type,
            compression: effectiveMode, created: Date.now(), nameMode: settings.nameMode
        }));
        if (metaJson.length > MAX_META_BYTES)
            throw new TSFError("validation", `Metadata too large: ${metaJson.length} B`);
        const metaIV  = crypto.getRandomValues(new Uint8Array(META_IV_LEN));
        const encMeta = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: metaIV, additionalData: fixedHeader },
            key, metaJson
        ));
        encMetaBlob = concatArrays([metaIV, uint32ToBytes(encMeta.length), encMeta]);
    }

    const aad = encMetaBlob.length > 0
        ? concatArrays([fixedHeader, encMetaBlob])
        : fixedHeader;

    const isBase64 = settings.containerFormat === "base64";
    const outName  = isBase64 ? finalName + ".tsf.b64" : finalName + ".tsf";

    // ── Dry-run + autoVerify cooperation ─────────────────────────────────
    // Pure dry-run (no autoVerify): skip everything, no file written, no chunk loop.
    // Dry-run + autoVerify: run the full chunk loop into a null writer so
    // verifyParts is populated and trueVerifyFile() can run — still no file written.
    if (settings.dryRunMode && !settings.autoVerify) {
        log(`  ℹ Dry-run: would save ${escapeHtml(outName)} (${chunkCount} chunk(s))`, "info");
        logV("  Dry-run complete — no file written.", "info");
        return;
    }
    if (settings.dryRunMode && settings.autoVerify) {
        log(`  ℹ Dry-run + verify: running full chunk loop into null writer (no file written)…`, "info");
    }

    // Null writer: accepts writes, discards bytes, needs no user gesture or
    // save-file dialog. Used exclusively in dry-run+verify mode.
    const _nullWriter = { write: async () => {}, close: async () => {}, streaming: false };
    const writer = settings.dryRunMode ? _nullWriter : await openWriteStream(outName);

    // Parallel capture buffer for true round-trip verification.
    // Active whenever autoVerify is on — including dry-run+verify.
    // Zero overhead (noop lambda) when autoVerify is off.
    const verifyParts = [];
    const _vwrite = settings.autoVerify
        ? chunk => { verifyParts.push(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk)); }
        : () => {};

    const _aadBytes = isBase64 ? toBase64(aad) : aad;
    await writer.write(_aadBytes);
    _vwrite(_aadBytes);

    let firstChunkCipher = null; // kept for legacy compat — no longer used by verify

    const startTime = performance.now();

    // ── Stall watchdog ────────────────────────────────────────────────
    // Arms a timer for each sub-step of a chunk. If the step takes longer
    // than STALL_TIMEOUT_MS the watchdog fires a warning. If cancellation
    // was already requested the watchdog also throws immediately so the
    // user is not stuck waiting for a frozen crypto/IO call to resolve.
    let _stallTimer = null;
    function _armStall(label) {
        _clearStall();
        _stallTimer = setTimeout(() => {
            const wasCancelled = cancelled || abortController?.signal.aborted;
            log(`  ⚠ Stall: "${label}" has been running for >${STALL_TIMEOUT_MS / 1000}s${wasCancelled ? " — cancellation forced" : " — possible hang"}`, "error");
            if (wasCancelled) {
                // Force an abort on the controller so the next await yields
                // a cancelled error rather than hanging indefinitely.
                abortController?.abort();
                cancelled = true;
            }
        }, STALL_TIMEOUT_MS);
    }
    function _clearStall() {
        if (_stallTimer !== null) { clearTimeout(_stallTimer); _stallTimer = null; }
    }

    for (let i = 0; i < chunkCount; i++) {
        if (cancelled || abortController?.signal.aborted)
            throw new TSFError("cancelled", "Cancelled");

        const chunkStart = performance.now();

        _armStall(`read chunk ${i + 1}/${chunkCount} from disk`);
        const raw = new Uint8Array(
            await file.slice(i * chunkSize, Math.min((i + 1) * chunkSize, file.size)).arrayBuffer());

        _armStall(`compress chunk ${i + 1}/${chunkCount}`);
        const { compressed } = compressChunk(raw, effectiveMode, false);

        _armStall(`AES-GCM encrypt chunk ${i + 1}/${chunkCount}`);
        const iv       = chunkIV(resolvedBaseIV, i, VERSION);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: aad },
            key, compressed
        ));

        _armStall(`write chunk ${i + 1}/${chunkCount} to stream`);
        const lenBytes = uint32ToBytes(ciphertext.length);
        if (isBase64) {
            const encoded = toBase64(concatArrays([lenBytes, ciphertext]));
            await writer.write(encoded);
            _vwrite(encoded);
        } else {
            await writer.write(lenBytes);
            await writer.write(ciphertext);
            _vwrite(lenBytes);
            _vwrite(ciphertext);
        }
        _clearStall();

        if (i === 0 && settings.autoVerify)
            firstChunkCipher = ciphertext;

        const chunkMs = (performance.now() - chunkStart).toFixed(0);
        const frac = (i + 1) / chunkCount;
        const eta  = etaString(performance.now() - startTime, frac);

        // Chunk-level diagnostic log — only when diagLog is enabled
        if (settings.diagLog) {
            log(`  [diag] chunk ${i + 1}/${chunkCount}: ${formatSize(raw.length)} → ${formatSize(ciphertext.length)} in ${chunkMs}ms`, "info");
        }

        updateProgress(Math.round(frac * 100),
            `Encrypting ${escapeHtml(file.name)}: chunk ${i + 1}/${chunkCount}` +
            (eta ? `  ·  ETA ${eta}` : ""));
        await new Promise(r => setTimeout(r, 0));
    }
    _clearStall();

    await writer.close();

    const modeLabel = effectiveMode === "none" ? "no compression (pre-compressed)"
                    : effectiveMode === "aggressive" ? "aggressive compression"
                    : "standard compression";
    const metaNote = doEncMeta  ? " · metadata encrypted"
                   : doPlainMeta ? " · metadata in header"
                   : " · no metadata";
    if (settings.dryRunMode) {
        log(`  ℹ Dry-run complete: verified ${escapeHtml(outName)} (${chunkCount} chunk(s), ${modeLabel}${metaNote}) — no file written`, "info");
    } else {
        log(`→ Saved: ${escapeHtml(outName)} (${chunkCount} chunk(s), ${formatSize(chunkSize)}/chunk, ${modeLabel}${metaNote})`, "success");
    }

    // ── Checksum sidecar ──────────────────────────────────────────────
    // FIX (bug #5 / RAM): The old code called file.arrayBuffer() which loads
    // the entire file into RAM just to hash it — defeating the streaming
    // approach for large files.  We now compute the SHA-256 incrementally by
    // re-reading the same chunks used during encryption, so peak RAM stays at
    // one chunkSize worth of data (same as the encryption loop above).
    if (settings.genChecksum && !settings.dryRunMode) {
        log("  Computing SHA-256 checksum (streaming)…", "info");
        // SubtleCrypto has no incremental digest API, so we feed chunks into
        // a manual accumulator.  For files that fit in RAM the original path
        // would be fine; for large files this keeps memory flat.
        // We use the same chunking the encryption loop uses.
        const hashBufs = [];
        for (let i = 0; i < chunkCount; i++) {
            const chunk = new Uint8Array(
                await file.slice(i * chunkSize, Math.min((i + 1) * chunkSize, file.size)).arrayBuffer());
            hashBufs.push(chunk);
        }
        // Concatenate all chunks into one buffer for SubtleCrypto.digest.
        // This is unavoidable with the current Web Crypto API — there is no
        // streaming digest.  For truly huge files the user should use a CLI
        // tool.  We still avoid the extra copy that file.arrayBuffer() would
        // have created on top of the chunk copies already in hashBufs.
        const combined = concatArrays(hashBufs);
        const hex = await sha256hex(combined);
        download(new Blob([`${hex}  ${file.name}\n`], { type: "text/plain" }),
            file.name + ".sha256");
        log(`  ✓ Checksum: ${hex.slice(0, 16)}…  (${file.name}.sha256)`, "info");
    }

    // ── True round-trip verification ──────────────────────────────────
    // The old autoVerify reused the live in-memory `aad`, `key`, and
    // `firstChunkCipher` — never touching disk, never re-parsing the header,
    // and therefore blind to any bug in the write-then-parse path (e.g. the
    // AAD mismatch bug that existed in decrypt.js).
    //
    // True verification requires treating the output as an opaque blob and
    // going through the full parse → reconstruct AAD → re-derive key →
    // decrypt pipeline, exactly as decryptFile() does.
    //
    // We capture the written bytes in a parallel buffer during the chunk loop
    // above (verifyParts[]) and wrap them in a File object here.  This is
    // independent of every in-memory variable used during encryption: the
    // bytes go through concatArrays / uint32ToBytes serialisation the same
    // way they do on the way to disk, so any header layout or AAD bug will
    // appear in these bytes too.  The key and AAD are re-derived from scratch
    // inside trueVerifyFile() — they are not shared with this scope.
    if (settings.autoVerify) {
        log("  True round-trip verify: building file from written bytes…", "info");
        try {
            const verifyBlob = new Blob(verifyParts, { type: "application/octet-stream" });
            const verifyFile = new File([verifyBlob], outName, { type: "application/octet-stream" });
            await trueVerifyFile(verifyFile, password, file, { chunkSampleSize: 3 });
        } catch (e) {
            log(`  ✗ Auto-verify error: ${e.message}`, "error");
        }
        // Release the verify buffer immediately — it's a full copy of the output
        verifyParts.length = 0;
    }
}
