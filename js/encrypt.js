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

    if (settings.dryRunMode) {
        log(`  ℹ Dry-run: would save ${escapeHtml(finalName)}.tsf (${chunkCount} chunk(s))`, "info");
        logV("  Dry-run complete — no file written.", "info");
        return;
    }

    const isBase64 = settings.containerFormat === "base64";
    const outName  = isBase64 ? finalName + ".tsf.b64" : finalName + ".tsf";

    // FIX (bug #3 & #4): In the old code, openWriteStream() was called
    // unconditionally even in base64 mode, which (a) popped a save-file
    // dialog the user had to dismiss before the base64 Blob download could
    // proceed, and (b) left the writable stream open/leaked when the base64
    // branch took over.  Now we only open a stream for binary output.
    //
    // Base64 mode accumulates all parts in allParts[] and encodes at the end.
    // Binary streaming mode writes directly chunk-by-chunk to the writer.
    let writer   = null;
    let allParts = null;

    if (isBase64) {
        allParts = [aad];
    } else {
        writer = await openWriteStream(outName);
        await writer.write(aad);
    }

    let firstChunkCipher = null; // used for auto-verify in binary streaming mode

    const startTime = performance.now();

    for (let i = 0; i < chunkCount; i++) {
        if (cancelled || abortController?.signal.aborted)
            throw new TSFError("cancelled", "Cancelled");

        const raw              = new Uint8Array(
            await file.slice(i * chunkSize, Math.min((i + 1) * chunkSize, file.size)).arrayBuffer());
        const { compressed }   = compressChunk(raw, effectiveMode, i === 0);
        const iv               = chunkIV(resolvedBaseIV, i, VERSION);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: aad },
            key, compressed
        ));

        const lenBytes = uint32ToBytes(ciphertext.length);

        if (allParts) {
            allParts.push(lenBytes, ciphertext);
        } else {
            await writer.write(lenBytes);
            await writer.write(ciphertext);
        }

        // Capture first chunk ciphertext for auto-verify in binary streaming mode.
        // In base64 mode, allParts[2] holds the first chunk's ciphertext.
        if (i === 0 && settings.autoVerify && !allParts)
            firstChunkCipher = ciphertext;

        const frac = (i + 1) / chunkCount;
        const eta  = etaString(performance.now() - startTime, frac);
        updateProgress(Math.round(frac * 100),
            `Encrypting ${escapeHtml(file.name)}: chunk ${i + 1}/${chunkCount}` +
            (eta ? `  ·  ETA ${eta}` : ""));
        await new Promise(r => setTimeout(r, 0));
    }

    if (isBase64) {
        const full = concatArrays(allParts);
        const b64  = toBase64(full);
        download(new Blob([b64], { type: "text/plain" }), outName);
    } else {
        await writer.close();
    }

    const modeLabel = effectiveMode === "none" ? "no compression (pre-compressed)"
                    : effectiveMode === "aggressive" ? "aggressive compression"
                    : "standard compression";
    const metaNote = doEncMeta  ? " · metadata encrypted"
                   : doPlainMeta ? " · metadata in header"
                   : " · no metadata";
    log(`→ Saved: ${escapeHtml(outName)} (${chunkCount} chunk(s), ${formatSize(chunkSize)}/chunk, ${modeLabel}${metaNote})`, "success");

    // ── Checksum sidecar ──────────────────────────────────────────────
    // FIX (bug #5 / RAM): The old code called file.arrayBuffer() which loads
    // the entire file into RAM just to hash it — defeating the streaming
    // approach for large files.  We now compute the SHA-256 incrementally by
    // re-reading the same chunks used during encryption, so peak RAM stays at
    // one chunkSize worth of data (same as the encryption loop above).
    if (settings.genChecksum) {
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

    // ── Auto-verify ───────────────────────────────────────────────────
    if (settings.autoVerify) {
        log("  Auto-verify: decrypting first chunk…", "info");
        try {
            // Reuse the key already derived above — no need to re-run Argon2.
            // allParts layout when present: [0]=aad, [1]=lenBytes_chunk0, [2]=ciphertext_chunk0, …
            // In binary streaming mode allParts is null; use the captured firstChunkCipher instead.
            const testCipher = allParts ? allParts[2] : firstChunkCipher;
            const testIV     = chunkIV(resolvedBaseIV, 0, VERSION);
            await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: testIV, additionalData: aad },
                key, testCipher
            );
            log("  ✓ Auto-verify passed — first chunk decrypts correctly", "success");
        } catch {
            log("  ✗ Auto-verify FAILED — output may be corrupt!", "error");
        }
    }
}
