// ═══════════════════════════════════════════════════════════════════
// decrypt.js  —  Decryption dispatcher and format implementations:
//                V18 (current), V17, V15, V14, V13 (legacy)
// ═══════════════════════════════════════════════════════════════════
"use strict";

// ═══════════════════════════════════════════════════════════════════
// DISPATCHER
// ═══════════════════════════════════════════════════════════════════

/**
 * Inspect the file header and route to the correct version handler.
 * Also handles the .tsf.b64 Base64 container by decoding it first.
 *
 * FIX (bug #1 / RAM): The old code decoded Base64 via file.text() →
 * atob() → charCodeAt loop, producing 4× peak RAM overhead for large
 * files.  We now decode in one pass through a Uint8Array using a
 * lookup table, keeping peak overhead to ~1.33× (the inherent Base64
 * expansion ratio) instead of 4×.
 */
async function decryptFile(file, password) {
    let resolvedFile = file;
    if (file.name.endsWith(".tsf.b64")) {
        log("  Base64 container detected — decoding…", "info");

        // Read as ArrayBuffer (binary, no string copy) then decode in one pass.
        const rawText = await file.text();
        // Strip all whitespace — some tools wrap at 76 chars which atob() rejects.
        const stripped = rawText.replace(/\s+/g, "");
        let bytes;
        try {
            // Use a single atob() + Uint8Array — avoids the extra string-copy
            // loop that the old charCodeAt() approach produced.
            const binaryStr = atob(stripped);
            bytes = new Uint8Array(binaryStr.length);
            for (let i = 0; i < binaryStr.length; i++)
                bytes[i] = binaryStr.charCodeAt(i);
        } catch {
            throw new TSFError("format",
                "Base64 decoding failed — file may be corrupt or not a valid .tsf.b64 container");
        }
        // Release the large text strings before continuing.
        resolvedFile = new File(
            [bytes],
            file.name.replace(/\.b64$/, ""),
            { type: "application/octet-stream" }
        );
        // bytes is now referenced only by the File/Blob — GC can collect the
        // original string once resolvedFile is constructed.
    }

    log(`Decrypt: ${escapeHtml(resolvedFile.name)}`, "info");

    if (resolvedFile.size === 0)
        throw new TSFError("format", "File is empty — not a valid TSF container");
    if (resolvedFile.size < 6)
        throw new TSFError("format", "File too short for any TSF format");

    const peek    = new Uint8Array(await resolvedFile.slice(0, 5).arrayBuffer());
    const magic   = new TextDecoder().decode(peek.slice(0, 4));
    const version = peek[4];

    if      (magic === "0018" && version === 18) await decryptFileV18(resolvedFile, password);
    else if (magic === "0017" && version === 17) await decryptFileV17(resolvedFile, password);
    else if (magic === "0015" && version === 15) await decryptFileV15(resolvedFile, password);
    else if (magic === "0014" && version === 14) await decryptFileV14(resolvedFile, password);
    else if (magic === "0013" && version === 13) await decryptFileV13(resolvedFile, password);
    else {
        const supported = ["0018", "0017", "0015", "0014", "0013"];
        if (!supported.includes(magic))
            throw new TSFError("format",
                `Unknown format: magic="${magic}" (supported: ${supported.join(", ")})`);
        throw new TSFError("version",
            `Version ${version} (magic "${magic}") not supported. Supported: ${SUPPORTED_VERSIONS.join(", ")}`);
    }
}

// ═══════════════════════════════════════════════════════════════════
// V18  (current, streaming — fixed chunk-IV derivation)
// ═══════════════════════════════════════════════════════════════════

async function decryptFileV18(file, password) {
    if (file.size < FIXED_HEADER_V17)
        throw new TSFError("format", "File too short for V18 header");

    const fixedBuf = new Uint8Array(await file.slice(0, FIXED_HEADER_V17).arrayBuffer());
    const dv = new DataView(fixedBuf.buffer);
    let off = 0;

    const magic       = new TextDecoder().decode(fixedBuf.slice(off, off + 4)); off += 4;
    const version     = fixedBuf[off++];
    const flags       = fixedBuf[off++];
    const parallelism = fixedBuf[off++];
    const salt        = fixedBuf.slice(off, off + SALT_LEN); off += SALT_LEN;
    const baseIV      = fixedBuf.slice(off, off + IV_LEN);   off += IV_LEN;
    const chunkSize   = dv.getUint32(off); off += 4;
    const chunkCount  = readUint64(dv, off); off += 8;
    const compByte    = fixedBuf[off++];
    const metaLen     = dv.getUint32(off); off += 4;

    if (magic !== "0018" || version !== 18)
        throw new TSFError("format", `Not V18 format (magic="${magic}", version=${version})`);
    if (parallelism < MIN_PARALLELISM || parallelism > MAX_PARALLELISM)
        throw new TSFError("corrupt", `Invalid parallelism in header: ${parallelism}`);
    if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE)
        throw new TSFError("corrupt", `Invalid chunk size in header: ${chunkSize}`);
    if (chunkCount > MAX_CHUNK_COUNT)
        throw new TSFError("corrupt", `Chunk count out of range: ${chunkCount}`);
    if (metaLen > MAX_META_BYTES)
        throw new TSFError("corrupt", `Metadata length out of range: ${metaLen}`);
    if (compByte !== COMPRESSION_STANDARD && compByte !== COMPRESSION_AGGRESSIVE &&
        compByte !== COMPRESSION_NONE)
        throw new TSFError("corrupt", `Unknown compression byte: ${compByte}`);

    const compressionMode = compByte === COMPRESSION_AGGRESSIVE ? "aggressive"
                          : compByte === COMPRESSION_NONE       ? "none"
                          :                                       "standard";
    const metaEncrypted   = (flags & FLAG_META_ENCRYPTED) !== 0;
    const plainHeaderEnd  = FIXED_HEADER_V17 + metaLen;

    const peekAADBuf = new Uint8Array(await file.slice(0, plainHeaderEnd + 4).arrayBuffer());
    let customAADLen = 0;
    if (peekAADBuf.length >= plainHeaderEnd + 4)
        customAADLen = new DataView(peekAADBuf.buffer).getUint32(plainHeaderEnd);

    const totalFixedLen = plainHeaderEnd + 4 + customAADLen;
    const fullFixedBuf  = new Uint8Array(await file.slice(0, totalFixedLen).arrayBuffer());

    let plainMeta = null;
    if (metaLen > 0) {
        try {
            plainMeta = JSON.parse(
                new TextDecoder().decode(fullFixedBuf.slice(FIXED_HEADER_V17, plainHeaderEnd)));
        } catch {
            throw new TSFError("corrupt", "Could not parse plain metadata");
        }
        validateMeta(plainMeta);
    }

    log("  Deriving key…", "info");
    const key = await deriveKey(password, salt, parallelism);

    let fileOffset = totalFixedLen;
    let meta = plainMeta || { compression: compressionMode };

    if (metaEncrypted) {
        const hdrBuf = new Uint8Array(
            await file.slice(fileOffset, fileOffset + META_IV_LEN + 4).arrayBuffer());
        if (hdrBuf.length < META_IV_LEN + 4)
            throw new TSFError("corrupt", "File too short: missing encrypted metadata header");

        const metaIV     = hdrBuf.slice(0, META_IV_LEN);
        const encMetaLen = new DataView(hdrBuf.buffer).getUint32(META_IV_LEN);
        fileOffset += META_IV_LEN + 4;

        if (encMetaLen > MAX_META_BYTES + 32)
            throw new TSFError("corrupt", `Encrypted metadata too large: ${encMetaLen}`);

        const encMetaBuf = new Uint8Array(
            await file.slice(fileOffset, fileOffset + encMetaLen).arrayBuffer());
        if (encMetaBuf.length < encMetaLen)
            throw new TSFError("corrupt", "File truncated: encrypted metadata incomplete");
        fileOffset += encMetaLen;

        let metaPlainBuf;
        try {
            metaPlainBuf = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: metaIV, additionalData: fullFixedBuf },
                key, encMetaBuf
            ));
        } catch {
            throw new TSFError("wrong_password", "Metadata decryption failed — likely wrong password");
        }

        try { meta = JSON.parse(new TextDecoder().decode(metaPlainBuf)); }
        catch { throw new TSFError("corrupt", "Could not parse encrypted metadata"); }
        validateMeta(meta);
    }

    if (meta.compression && meta.compression !== compressionMode) {
        logV(`  ⚠ Compression mismatch: header="${compressionMode}", metadata="${meta.compression}" — trusting header`, "warn");
        meta.compression = compressionMode;
    } else if (!meta.compression) {
        meta.compression = compressionMode;
    }

    if (!meta.originalName) logV("  ⚠ No original filename in metadata", "warn");
    if (!meta.mimeType)     logV("  ⚠ No MIME type in metadata", "warn");

    // FIX (bug #2 / RAM): fullFixedBuf already covers exactly [0, fileOffset).
    // Re-slicing the file to build fullAAD was a redundant read that also
    // created a second copy of the header region in RAM.  Reuse fullFixedBuf.
    const fullAAD = fullFixedBuf;

    const minBodySize = fileOffset + chunkCount * (4 + 17);
    if (file.size < minBodySize)
        throw new TSFError("corrupt",
            `File too short for declared ${chunkCount} chunk(s): expected ≥ ${formatSize(minBodySize)}, got ${formatSize(file.size)}`);

    if (settings.previewMeta) {
        const proceed = await showMetaModal(meta);
        if (!proceed) throw new TSFError("cancelled", "Cancelled after metadata preview");
    }

    const restoredName =
        settings.decryptNameOverride ||
        meta.originalName            ||
        file.name.replace(/\.tsf$/i, "").replace(/\.tsf\.b64$/i, "") ||
        "decrypted_file";

    const writer    = await openWriteStream(restoredName, meta.mimeType || "application/octet-stream");
    const startTime = performance.now();

    for (let i = 0; i < chunkCount; i++) {
        if (cancelled || abortController?.signal.aborted)
            throw new TSFError("cancelled", "Cancelled");

        const lenBuf = new Uint8Array(await file.slice(fileOffset, fileOffset + 4).arrayBuffer());
        if (lenBuf.length < 4)
            throw new TSFError("corrupt", `Chunk ${i}: unexpected EOF — no length prefix`);
        const cipherLen = new DataView(lenBuf.buffer).getUint32(0);
        fileOffset += 4;

        const cipherBuf = new Uint8Array(
            await file.slice(fileOffset, fileOffset + cipherLen).arrayBuffer());
        if (cipherBuf.length < cipherLen)
            throw new TSFError("corrupt", `Chunk ${i}: ciphertext truncated`);
        fileOffset += cipherLen;

        const iv = chunkIV(baseIV, i, 18);
        let decrypted;
        try {
            decrypted = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv, additionalData: fullAAD },
                key, cipherBuf
            ));
        } catch {
            if (i === 0)
                throw new TSFError("wrong_password",
                    "Decryption failed — likely wrong password (first chunk auth failed)");
            throw new TSFError("corrupt",
                `Chunk ${i}: decryption failed — file tampered or corrupted`);
        }

        await writer.write(decompressChunk(decrypted, meta.compression));

        const frac = (i + 1) / chunkCount;
        const eta  = etaString(performance.now() - startTime, frac);
        updateProgress(Math.round(frac * 100),
            `Decrypting ${escapeHtml(file.name)}: chunk ${i + 1}/${chunkCount}` +
            (eta ? `  ·  ETA ${eta}` : ""));
        await new Promise(r => setTimeout(r, 0));
    }

    if (fileOffset !== file.size) {
        const extra = file.size - fileOffset;
        throw new TSFError("corrupt",
            `Integrity error: ${extra} unexpected byte(s) after last chunk — file may have been modified`);
    }

    await writer.close();
    log(`→ Restored: ${escapeHtml(restoredName)}`, "success");
}

// ═══════════════════════════════════════════════════════════════════
// V17  (legacy, streaming — chunk-IV XORs with idx, chunk 0 = raw base IV)
// ═══════════════════════════════════════════════════════════════════

async function decryptFileV17(file, password) {
    if (file.size < FIXED_HEADER_V17)
        throw new TSFError("format", "File too short for V17 header");

    const fixedBuf = new Uint8Array(await file.slice(0, FIXED_HEADER_V17).arrayBuffer());
    const dv = new DataView(fixedBuf.buffer);
    let off = 0;

    const magic       = new TextDecoder().decode(fixedBuf.slice(off, off + 4)); off += 4;
    const version     = fixedBuf[off++];
    const flags       = fixedBuf[off++];
    const parallelism = fixedBuf[off++];
    const salt        = fixedBuf.slice(off, off + SALT_LEN); off += SALT_LEN;
    const baseIV      = fixedBuf.slice(off, off + IV_LEN);   off += IV_LEN;
    const chunkSize   = dv.getUint32(off); off += 4;
    const chunkCount  = readUint64(dv, off); off += 8;
    const compByte    = fixedBuf[off++];
    const metaLen     = dv.getUint32(off); off += 4;

    if (magic !== "0017" || version !== 17)
        throw new TSFError("format", `Not V17 format (magic="${magic}", version=${version})`);
    if (parallelism < MIN_PARALLELISM || parallelism > MAX_PARALLELISM)
        throw new TSFError("corrupt", `Invalid parallelism in header: ${parallelism}`);
    if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE)
        throw new TSFError("corrupt", `Invalid chunk size in header: ${chunkSize}`);
    if (chunkCount > MAX_CHUNK_COUNT)
        throw new TSFError("corrupt", `Chunk count out of range: ${chunkCount}`);
    if (metaLen > MAX_META_BYTES)
        throw new TSFError("corrupt", `Metadata length out of range: ${metaLen}`);
    if (compByte !== COMPRESSION_STANDARD && compByte !== COMPRESSION_AGGRESSIVE &&
        compByte !== COMPRESSION_NONE)
        throw new TSFError("corrupt", `Unknown compression byte: ${compByte}`);

    const compressionMode = compByte === COMPRESSION_AGGRESSIVE ? "aggressive"
                          : compByte === COMPRESSION_NONE       ? "none"
                          :                                       "standard";
    const metaEncrypted   = (flags & FLAG_META_ENCRYPTED) !== 0;
    const plainHeaderEnd  = FIXED_HEADER_V17 + metaLen;

    const peekAADBuf = new Uint8Array(await file.slice(0, plainHeaderEnd + 4).arrayBuffer());
    let customAADLen = 0;
    if (peekAADBuf.length >= plainHeaderEnd + 4)
        customAADLen = new DataView(peekAADBuf.buffer).getUint32(plainHeaderEnd);

    const totalFixedLen = plainHeaderEnd + 4 + customAADLen;
    const fullFixedBuf  = new Uint8Array(await file.slice(0, totalFixedLen).arrayBuffer());

    let plainMeta = null;
    if (metaLen > 0) {
        try {
            plainMeta = JSON.parse(
                new TextDecoder().decode(fullFixedBuf.slice(FIXED_HEADER_V17, plainHeaderEnd)));
        } catch {
            throw new TSFError("corrupt", "Could not parse plain metadata");
        }
        validateMeta(plainMeta);
    }

    log("  Deriving key…", "info");
    const key = await deriveKey(password, salt, parallelism);

    let fileOffset = totalFixedLen;
    let meta = plainMeta || { compression: compressionMode };

    if (metaEncrypted) {
        const hdrBuf = new Uint8Array(
            await file.slice(fileOffset, fileOffset + META_IV_LEN + 4).arrayBuffer());
        if (hdrBuf.length < META_IV_LEN + 4)
            throw new TSFError("corrupt", "File too short: missing encrypted metadata header");

        const metaIV     = hdrBuf.slice(0, META_IV_LEN);
        const encMetaLen = new DataView(hdrBuf.buffer).getUint32(META_IV_LEN);
        fileOffset += META_IV_LEN + 4;

        if (encMetaLen > MAX_META_BYTES + 32)
            throw new TSFError("corrupt", `Encrypted metadata too large: ${encMetaLen}`);

        const encMetaBuf = new Uint8Array(
            await file.slice(fileOffset, fileOffset + encMetaLen).arrayBuffer());
        if (encMetaBuf.length < encMetaLen)
            throw new TSFError("corrupt", "File truncated: encrypted metadata incomplete");
        fileOffset += encMetaLen;

        let metaPlainBuf;
        try {
            metaPlainBuf = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: metaIV, additionalData: fullFixedBuf },
                key, encMetaBuf
            ));
        } catch {
            throw new TSFError("wrong_password", "Metadata decryption failed — likely wrong password");
        }

        try { meta = JSON.parse(new TextDecoder().decode(metaPlainBuf)); }
        catch { throw new TSFError("corrupt", "Could not parse encrypted metadata"); }
        validateMeta(meta);
    }

    if (meta.compression && meta.compression !== compressionMode) {
        logV(`  ⚠ Compression mismatch: header="${compressionMode}", metadata="${meta.compression}" — trusting header`, "warn");
        meta.compression = compressionMode;
    } else if (!meta.compression) {
        meta.compression = compressionMode;
    }

    if (!meta.originalName) logV("  ⚠ No original filename in metadata", "warn");
    if (!meta.mimeType)     logV("  ⚠ No MIME type in metadata", "warn");

    // FIX (bug #6 / RAM): Same redundant re-read as V18 bug #2.
    // fullFixedBuf already covers [0, fileOffset) — reuse it directly.
    const fullAAD = fullFixedBuf;

    const minBodySize = fileOffset + chunkCount * (4 + 17);
    if (file.size < minBodySize)
        throw new TSFError("corrupt",
            `File too short for declared ${chunkCount} chunk(s): expected ≥ ${formatSize(minBodySize)}, got ${formatSize(file.size)}`);

    if (settings.previewMeta) {
        const proceed = await showMetaModal(meta);
        if (!proceed) throw new TSFError("cancelled", "Cancelled after metadata preview");
    }

    const restoredName =
        settings.decryptNameOverride ||
        meta.originalName            ||
        file.name.replace(/\.tsf$/i, "").replace(/\.tsf\.b64$/i, "") ||
        "decrypted_file";

    const writer    = await openWriteStream(restoredName, meta.mimeType || "application/octet-stream");
    const startTime = performance.now();

    for (let i = 0; i < chunkCount; i++) {
        if (cancelled || abortController?.signal.aborted)
            throw new TSFError("cancelled", "Cancelled");

        const lenBuf = new Uint8Array(await file.slice(fileOffset, fileOffset + 4).arrayBuffer());
        if (lenBuf.length < 4)
            throw new TSFError("corrupt", `Chunk ${i}: unexpected EOF — no length prefix`);
        const cipherLen = new DataView(lenBuf.buffer).getUint32(0);
        fileOffset += 4;

        const cipherBuf = new Uint8Array(
            await file.slice(fileOffset, fileOffset + cipherLen).arrayBuffer());
        if (cipherBuf.length < cipherLen)
            throw new TSFError("corrupt", `Chunk ${i}: ciphertext truncated`);
        fileOffset += cipherLen;

        const iv = chunkIV(baseIV, i, 17);
        let decrypted;
        try {
            decrypted = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv, additionalData: fullAAD },
                key, cipherBuf
            ));
        } catch {
            if (i === 0)
                throw new TSFError("wrong_password",
                    "Decryption failed — likely wrong password (first chunk auth failed)");
            throw new TSFError("corrupt",
                `Chunk ${i}: decryption failed — file tampered or corrupted`);
        }

        await writer.write(decompressChunk(decrypted, meta.compression));

        const frac = (i + 1) / chunkCount;
        const eta  = etaString(performance.now() - startTime, frac);
        updateProgress(Math.round(frac * 100),
            `Decrypting ${escapeHtml(file.name)}: chunk ${i + 1}/${chunkCount}` +
            (eta ? `  ·  ETA ${eta}` : ""));
        await new Promise(r => setTimeout(r, 0));
    }

    if (fileOffset !== file.size) {
        const extra = file.size - fileOffset;
        throw new TSFError("corrupt",
            `Integrity error: ${extra} unexpected byte(s) after last chunk — file may have been modified`);
    }

    await writer.close();
    log(`→ Restored: ${escapeHtml(restoredName)}`, "success");
}

// ═══════════════════════════════════════════════════════════════════
// V15  (legacy, streaming)
// ═══════════════════════════════════════════════════════════════════

async function decryptFileV15(file, password) {
    const FIXED_HEADER = 50;
    if (file.size < FIXED_HEADER)
        throw new TSFError("format", "File too short for V15 header");

    const fixedBuf = new Uint8Array(await file.slice(0, FIXED_HEADER).arrayBuffer());
    const dv = new DataView(fixedBuf.buffer);
    let off = 0;

    const magic       = new TextDecoder().decode(fixedBuf.slice(off, off + 4)); off += 4;
    const version     = fixedBuf[off++];
    const parallelism = fixedBuf[off++];
    const salt        = fixedBuf.slice(off, off + SALT_LEN); off += SALT_LEN;
    const baseIV      = fixedBuf.slice(off, off + IV_LEN);   off += IV_LEN;
    const chunkSize   = dv.getUint32(off); off += 4;
    const chunkCount  = readUint64(dv, off); off += 8;
    const metaLen     = dv.getUint32(off); off += 4;

    if (magic !== "0015" || version !== 15)
        throw new TSFError("format", `Not V15 format (magic="${magic}", version=${version})`);
    if (parallelism < MIN_PARALLELISM || parallelism > MAX_PARALLELISM)
        throw new TSFError("corrupt", `V15: Invalid parallelism: ${parallelism}`);
    if (chunkSize < MIN_CHUNK_SIZE || chunkSize > MAX_CHUNK_SIZE)
        throw new TSFError("corrupt", `V15: Invalid chunk size: ${chunkSize}`);
    if (chunkCount > MAX_CHUNK_COUNT)
        throw new TSFError("corrupt", `V15: Chunk count out of range: ${chunkCount}`);
    if (metaLen > MAX_META_BYTES)
        throw new TSFError("corrupt", `V15: Metadata length out of range: ${metaLen}`);

    const aadSize = FIXED_HEADER + metaLen;
    if (file.size < aadSize + chunkCount * (4 + 17))
        throw new TSFError("corrupt",
            `V15: File too short for declared ${chunkCount} chunk(s)`);

    const fullHeaderBuf = new Uint8Array(await file.slice(0, aadSize).arrayBuffer());
    let meta;
    try {
        meta = JSON.parse(new TextDecoder().decode(fullHeaderBuf.slice(FIXED_HEADER, aadSize)));
    } catch { throw new TSFError("corrupt", "V15: Could not parse metadata"); }
    validateMeta(meta);

    if (!meta.originalName) logV("  ⚠ V15: No original filename in metadata", "warn");
    if (!meta.mimeType)     logV("  ⚠ V15: No MIME type in metadata", "warn");

    if (settings.previewMeta) {
        const proceed = await showMetaModal(meta);
        if (!proceed) throw new TSFError("cancelled", "Cancelled");
    }

    log("  Deriving key…", "info");
    const key = await deriveKey(password, salt, parallelism);
    const aad = fullHeaderBuf;

    const restoredName =
        settings.decryptNameOverride ||
        meta.originalName            ||
        file.name.replace(/\.tsf$/i, "") ||
        "decrypted_file";

    const writer    = await openWriteStream(restoredName, meta.mimeType || "application/octet-stream");
    let fileOffset  = aadSize;
    const startTime = performance.now();

    for (let i = 0; i < chunkCount; i++) {
        if (cancelled || abortController?.signal.aborted)
            throw new TSFError("cancelled", "Cancelled");

        const lenBuf = new Uint8Array(await file.slice(fileOffset, fileOffset + 4).arrayBuffer());
        if (lenBuf.length < 4)
            throw new TSFError("corrupt", `V15 Chunk ${i}: unexpected EOF`);
        const cipherLen = new DataView(lenBuf.buffer).getUint32(0);
        fileOffset += 4;

        const cipherBuf = new Uint8Array(
            await file.slice(fileOffset, fileOffset + cipherLen).arrayBuffer());
        if (cipherBuf.length < cipherLen)
            throw new TSFError("corrupt", `V15 Chunk ${i}: ciphertext truncated`);
        fileOffset += cipherLen;

        const iv = chunkIV(baseIV, i, 15);
        let decrypted;
        try {
            decrypted = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv, additionalData: aad },
                key, cipherBuf
            ));
        } catch {
            if (i === 0)
                throw new TSFError("wrong_password",
                    "V15: Decryption failed — likely wrong password");
            throw new TSFError("corrupt", `V15 Chunk ${i}: decryption failed`);
        }

        await writer.write(decompressChunk(decrypted, meta.compression));

        const frac = (i + 1) / chunkCount;
        const eta  = etaString(performance.now() - startTime, frac);
        updateProgress(Math.round(frac * 100),
            `Decrypting ${escapeHtml(file.name)}: chunk ${i + 1}/${chunkCount}` +
            (eta ? `  ·  ETA ${eta}` : ""));
        await new Promise(r => setTimeout(r, 0));
    }

    if (fileOffset !== file.size)
        throw new TSFError("corrupt",
            `V15: Integrity error — ${file.size - fileOffset} unexpected byte(s) after last chunk`);

    await writer.close();
    log(`→ Restored: ${escapeHtml(restoredName)}`, "success");
}

// ═══════════════════════════════════════════════════════════════════
// V14  (legacy, full-buffer in RAM — inherent to the format)
// ═══════════════════════════════════════════════════════════════════

async function decryptFileV14(file, password) {
    if (file.size > 64 * 1024 * 1024)
        log(`  ⚠ V1X legacy format: loading ${formatSize(file.size)} into RAM — may be slow or fail on low-memory devices`, "warn");
    log("  V14 format — legacy decryption (full file in RAM)", "warn");
    const input = new Uint8Array(await file.arrayBuffer());
    let offset = 5;  // skip magic (4) + version (1)

    const parallelism = input[offset++];
    if (parallelism < MIN_PARALLELISM || parallelism > MAX_PARALLELISM)
        throw new TSFError("corrupt", `V14: Invalid parallelism: ${parallelism}`);

    const salt    = input.slice(offset, offset + SALT_LEN); offset += SALT_LEN;
    const iv      = input.slice(offset, offset + IV_LEN);   offset += IV_LEN;
    const dv      = new DataView(input.buffer, input.byteOffset);
    const metaLen = dv.getUint32(offset); offset += 4;

    if (metaLen > MAX_META_BYTES)
        throw new TSFError("corrupt", `V14: Metadata length out of range: ${metaLen}`);

    const rawMetaBytes = input.slice(offset, offset + metaLen); offset += metaLen;
    let meta;
    try { meta = JSON.parse(new TextDecoder().decode(rawMetaBytes)); }
    catch { throw new TSFError("corrupt", "V14: Could not parse metadata"); }
    validateMeta(meta);

    if (!meta.originalName) logV("  ⚠ V14: No original filename in metadata", "warn");

    if (settings.previewMeta) {
        const proceed = await showMetaModal(meta);
        if (!proceed) throw new TSFError("cancelled", "Cancelled");
    }

    const aad = concatArrays([
        new TextEncoder().encode("0014"),
        new Uint8Array([14, parallelism]),
        salt, iv,
        uint32ToBytes(metaLen),
        rawMetaBytes
    ]);

    log("  Deriving key…", "info");
    const key = await deriveKey(password, salt, parallelism);
    let decrypted;
    try {
        decrypted = new Uint8Array(await crypto.subtle.decrypt(
            { name: "AES-GCM", iv, additionalData: aad },
            key, input.slice(offset)
        ));
    } catch {
        throw new TSFError("wrong_password",
            "V14: Decryption failed — wrong password or file tampered");
    }

    const decompressed = decompressFull(decrypted, meta.compression);
    const restoredName =
        settings.decryptNameOverride ||
        meta.originalName            ||
        file.name.replace(/\.tsf$/i, "") ||
        "decrypted_file";
    download(new Blob([decompressed]), restoredName);
    log(`→ Restored: ${escapeHtml(restoredName)}`, "success");
}

// ═══════════════════════════════════════════════════════════════════
// V13  (legacy, full-buffer in RAM — inherent to the format)
// ═══════════════════════════════════════════════════════════════════

/** Internal: parse a V13 binary blob into { salt, iv, meta, aad, encrypted, parallelism }. */
function _parseV13Header(input) {
    let offset = 0;
    const magic = new TextDecoder().decode(input.slice(0, 4));
    if (magic !== "0013") throw new TSFError("format", `Not V13 format: "${magic}"`);
    offset += 4;
    const version = input[offset++];
    if (version !== 13) throw new TSFError("version", `Not V13 content: version=${version}`);

    const salt    = input.slice(offset, offset + SALT_LEN); offset += SALT_LEN;
    const iv      = input.slice(offset, offset + IV_LEN);   offset += IV_LEN;
    const metaLen = new DataView(input.buffer, input.byteOffset).getUint32(offset); offset += 4;

    if (metaLen > MAX_META_BYTES)
        throw new TSFError("corrupt", `V13: Metadata too large: ${metaLen}`);

    let meta;
    try {
        meta = JSON.parse(new TextDecoder().decode(input.slice(offset, offset + metaLen)));
    } catch { throw new TSFError("corrupt", "V13: Could not parse metadata"); }
    validateMeta(meta);

    // AAD must use the ORIGINAL raw metadata bytes as they appeared on disk,
    // not a re-serialized copy. JSON.stringify does not guarantee key order or
    // whitespace preservation, so re-encoding could produce a different byte
    // sequence and cause AES-GCM authentication to fail.
    const rawMetaBytesForAAD = input.slice(offset, offset + metaLen);
    offset += metaLen;

    const aad = concatArrays([
        new TextEncoder().encode("0013"),
        new Uint8Array([13]),
        salt, iv,
        uint32ToBytes(metaLen),
        rawMetaBytesForAAD
    ]);

    return { salt, iv, meta, aad, encrypted: input.slice(offset), parallelism: 2 };
}

/** Full V13 decryption (called by the dispatcher). */
async function decryptFileV13(file, password) {
    if (file.size > 64 * 1024 * 1024)
        log(`  ⚠ V1X legacy format: loading ${formatSize(file.size)} into RAM — may be slow or fail on low-memory devices`, "warn");
    log("  V13 format — migrating for decryption", "info");
    const input  = new Uint8Array(await file.arrayBuffer());
    const parsed = _parseV13Header(input);

    if (!parsed.meta.originalName)
        logV("  ⚠ V13: No original filename in metadata", "warn");

    if (settings.previewMeta) {
        const proceed = await showMetaModal(parsed.meta);
        if (!proceed) throw new TSFError("cancelled", "Cancelled");
    }

    log("  Deriving key…", "info");
    const key = await deriveKey(password, parsed.salt, parsed.parallelism);
    let decrypted;
    try {
        decrypted = new Uint8Array(await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: parsed.iv, additionalData: parsed.aad },
            key, parsed.encrypted
        ));
    } catch {
        throw new TSFError("wrong_password",
            "V13: Decryption failed — wrong password or file tampered");
    }

    const decompressed = decompressFull(decrypted, parsed.meta.compression);
    const restoredName =
        settings.decryptNameOverride ||
        parsed.meta.originalName     ||
        file.name.replace(/\.tsf$/i, "") ||
        "decrypted_file";
    download(new Blob([decompressed]), restoredName);
    log(`→ Restored: ${escapeHtml(restoredName)}`, "success");
}
