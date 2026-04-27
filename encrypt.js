// ═══════════════════════════════════════════════════════════════════
// encrypt.js  —  V17 encryption (current format)
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

    // ── Salt ─────────────────────────────────────────────────────────
    let salt;
    if (settings.deterministicMode && settings.manualSalt && settings.manualSalt.length === 32) {
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

    logV("  KDF …", "info");
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

    const doEncMeta   = settings.keepMeta && settings.encryptMeta;
    const doPlainMeta = settings.keepMeta && !settings.encryptMeta;
    let flags = 0;
    if (doEncMeta) flags |= FLAG_META_ENCRYPTED;

    const compressionByte = mode === "aggressive" ? COMPRESSION_AGGRESSIVE : COMPRESSION_STANDARD;

    const plainMetaBytes = doPlainMeta
        ? (() => {
            const json  = JSON.stringify({
                originalName: file.name, mimeType: file.type,
                compression: mode, created: Date.now(), nameMode: settings.nameMode
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
            compression: mode, created: Date.now(), nameMode: settings.nameMode
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

    const outName = settings.containerFormat === "base64"
        ? finalName + ".tsf.b64"
        : finalName + ".tsf";

    const writer = await openWriteStream(outName);

    if (settings.containerFormat !== "base64")
        await writer.write(aad);

    const allParts  = [aad];
    const startTime = Date.now();

    for (let i = 0; i < chunkCount; i++) {
        if (cancelled || abortController?.signal.aborted)
            throw new TSFError("cancelled", "Cancelled");

        const raw        = new Uint8Array(
            await file.slice(i * chunkSize, Math.min((i + 1) * chunkSize, file.size)).arrayBuffer());
        const compressed = compressChunk(raw, mode);
        const iv         = chunkIV(resolvedBaseIV, i);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: aad },
            key, compressed
        ));

        const lenBytes = uint32ToBytes(ciphertext.length);

        if (settings.containerFormat === "base64") {
            allParts.push(lenBytes, ciphertext);
        } else {
            await writer.write(lenBytes);
            await writer.write(ciphertext);
        }

        const frac = (i + 1) / chunkCount;
        const eta  = etaString(Date.now() - startTime, frac);
        updateProgress(Math.round(frac * 100),
            `Encrypting ${escapeHtml(file.name)}: chunk ${i + 1}/${chunkCount}` +
            (eta ? `  ·  ETA ${eta}` : ""));
        await new Promise(r => setTimeout(r, 0));
    }

    if (settings.containerFormat === "base64") {
        const full = concatArrays(allParts);
        const b64  = toBase64(full);
        download(new Blob([b64], { type: "text/plain" }), outName);
    } else {
        await writer.close();
    }

    const metaNote = doEncMeta  ? " · metadata encrypted"
                   : doPlainMeta ? " · metadata in header"
                   : " · no metadata";
    log(`→ Saved: ${escapeHtml(outName)} (${chunkCount} chunk(s), ${formatSize(chunkSize)}/chunk${metaNote})`, "success");

    // ── Checksum sidecar ──────────────────────────────────────────────
    if (settings.genChecksum) {
        log("  Computing SHA-256 checksum…", "info");
        const fileBytes = new Uint8Array(await file.arrayBuffer());
        const hex = await sha256hex(fileBytes);
        download(new Blob([`${hex}  ${file.name}\n`], { type: "text/plain" }),
            file.name + ".sha256");
        log(`  ✓ Checksum: ${hex.slice(0, 16)}…  (${file.name}.sha256)`, "info");
    }

    // ── Auto-verify ───────────────────────────────────────────────────
    if (settings.autoVerify) {
        logV("  Auto-verify: re-deriving key for test decrypt…", "info");
        try {
            await deriveKey(password, salt, settings.argon2Parallel, {
                time: settings.argon2Time, mem: settings.argon2Mem
            });
            log("  ✓ Auto-verify passed — key derivation consistent", "success");
        } catch {
            log("  ✗ Auto-verify failed!", "error");
        }
    }
}
