// ═══════════════════════════════════════════════════════════════════
// processor.js  —  Queue processor (encrypt/decrypt batch) and cancel
// ═══════════════════════════════════════════════════════════════════
"use strict";

/** Reset UI to idle state — call on both normal completion and early returns. */
function _resetProcessUI() {
    document.getElementById("cancelBtn").disabled = true;
    abortController = null;
    isRunning = false;
}

/**
 * Validate inputs, then iterate over the file queue running encrypt or
 * decrypt for each entry. Handles progress, errors, and batch modes.
 *
 * @param {"encrypt"|"decrypt"} mode
 */
async function processQueue(mode) {
    if (isRunning) { alert("A process is already running. Please wait or cancel it first."); return; }
    isRunning = true;
    applySettings(true);
    const password = document.getElementById("password").value.normalize("NFC");
    try { validatePassword(password); }
    catch (err) { alert(err.message); isRunning = false; return; }

    // Confirm field required for encryption
    if (mode === "encrypt") {
        const confirm = document.getElementById("passwordConfirm").value;
        if (!confirm) {
            alert("Please confirm your password in the Confirm password field.");
            document.getElementById("passwordConfirm").focus();
            isRunning = false; return;
        }
        if (password !== confirm) {
            alert("Passwords do not match — please re-enter and confirm.");
            document.getElementById("passwordConfirm").focus();
            isRunning = false; return;
        }
    }

    if (queue.length === 0) { alert("No files in queue"); isRunning = false; return; }

    if (settings.useKeyfile && !keyfileData) {
        alert("Keyfile is enabled but no keyfile has been selected.");
        isRunning = false; return;
    }

    // ── Past all validation — safe to activate cancel button ──────────
    cancelled       = false;
    abortController = new AbortController();
    document.getElementById("cancelBtn").disabled = false;

    let successCount = 0;
    let errorCount   = 0;
    const errorTypes = {};

    logSep();
    log(`▶ ${mode === "encrypt" ? "Encrypting" : "Decrypting"} ${queue.length} file(s) …`, "info");
    if (settings.dryRunMode)
        log("  ℹ Dry-run mode active — no files will be written", "warn");
    if (settings.useAAD && settings.aadString)
        logV(`  ℹ Custom AAD: "${settings.aadString}"`, "info");

    try {
        for (let i = 0; i < queue.length; i++) {
            if (cancelled || abortController.signal.aborted) {
                log(`⛔ Aborted after ${i} of ${queue.length} file(s)`, "warn");
                break;
            }

            updateProgress(
                Math.round((i / queue.length) * 100),
                `File ${i + 1} of ${queue.length}: ${queue[i].name} (${formatSize(queue[i].size)})`
            );

            try {
                if (mode === "encrypt") await encryptFile(queue[i], password);
                else                    await decryptFile(queue[i], password);
                successCount++;
            } catch (err) {
                errorCount++;
                if (err instanceof TSFError) {
                    errorTypes[err.type] = (errorTypes[err.type] || 0) + 1;
                    const level = (err.type === "wrong_password" || err.type === "corrupt")
                        ? "error" : "warn";
                    log(`✗ ${escapeHtml(queue[i].name)}: ${err.message}`, level);
                    if (settings.batchMode === "fail-fast") {
                        log("  ⛔ Fail-fast: stopping after first error", "warn");
                        break;
                    }
                } else {
                    // Catch unexpected runtime errors (e.g. WASM failures, OOM)
                    const msg = err && err.message ? err.message : String(err);
                    log(`✗ ${escapeHtml(queue[i].name)}: Unexpected error — ${msg}`, "error");
                    log(`  ℹ If you see "CompileError" or "wasm", check that your browser supports WebAssembly and that no browser extension is blocking it.`, "warn");
                    if (settings.batchMode === "fail-fast") break;
                }
            }

            // Yield to keep the UI responsive between files
            await new Promise(r => setTimeout(r, 0));
        }
    } finally {
        updateProgress(100, `Done: ${successCount} succeeded, ${errorCount} failed`);

        logSep();
        log(`  ✓ Succeeded: ${successCount}`, "success");
        if (errorCount > 0) {
            log(`  ✗ Failed: ${errorCount}`, "error");
            const typeLabels = {
                wrong_password : "Wrong password",
                corrupt        : "File corrupted / integrity error",
                trailing_data  : "Trailing data detected",
                format         : "Unknown format",
                version        : "Unsupported version",
                size           : "File size limit exceeded",
                validation     : "Validation error",
                wasm           : "WebAssembly / Argon2 init failure",
                crypto         : "Key derivation error",
                cancelled      : "Cancelled",
            };
            for (const [type, count] of Object.entries(errorTypes))
                log(`    · ${typeLabels[type] || type}: ${count}`, "warn");
        }
        logSep();

        _resetProcessUI();
    }
}

/** Request cancellation of the running queue (current chunk finishes first,
 *  or is force-aborted by the stall watchdog if it appears frozen). */
function cancelProcess() {
    cancelled = true;
    if (abortController) abortController.abort();
    log("⛔ Cancellation requested — stopping after current chunk (or immediately if frozen)…", "warn");
    document.getElementById("cancelBtn").disabled = true;
}
