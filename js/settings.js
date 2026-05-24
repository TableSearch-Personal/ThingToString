// ═══════════════════════════════════════════════════════════════════
// settings.js  —  Settings panel: read/apply UI values, Argon2 UI
//                 helpers, salt/nonce controls, AAD toggle, and
//                 config profile import/export
// ═══════════════════════════════════════════════════════════════════
"use strict";

// ── Name-mode toggle ─────────────────────────────────────────────────

function onNameModeChange() {
    const mode = document.getElementById("nameMode").value;
    document.getElementById("customName").classList.toggle("visible", mode === "custom");
}

// ── Apply settings from UI to state object ───────────────────────────

function applySettings(silent = false) {
    // Simple settings — always applied
    settings.nameMode            = document.getElementById("nameMode").value;
    settings.customName          = document.getElementById("customName").value.trim();
    settings.compression         = document.getElementById("compressionMode").value;
    settings.keepMeta            = document.getElementById("keepMeta").checked;
    settings.encryptMeta         = document.getElementById("encryptMeta").checked;
    settings.chunkSize           = parseInt(document.getElementById("chunkSizeSelect").value, 10);
    settings.decryptNameOverride = document.getElementById("decryptNameOverride").value.trim();
    settings.previewMeta         = document.getElementById("previewMeta").checked;

    // Advanced settings — only applied when advanced mode is active
    if (isAdvancedMode) {
        settings.argon2Time     = Math.max(1,    Math.min(64,      parseInt(document.getElementById("argon2Time").value)     || ARGON2_TIME_DEFAULT));
        settings.argon2Mem      = Math.max(8192, Math.min(1048576, parseInt(document.getElementById("argon2Mem").value)      || ARGON2_MEM_DEFAULT));
        settings.argon2Parallel = Math.max(1,    Math.min(8,       parseInt(document.getElementById("argon2Parallel").value) || ARGON2_PARALLEL_LOCAL));
        settings.deterministicMode = document.getElementById("deterministicMode").checked;
        settings.manualSalt     = document.getElementById("manualSalt").value.trim();
        settings.useKeyfile     = document.getElementById("useKeyfile").checked;
        settings.useAAD         = document.getElementById("useAAD").checked;
        settings.aadString      = document.getElementById("aadString").value.trim();
        settings.containerFormat = document.getElementById("containerFormat").value;
        settings.genChecksum    = document.getElementById("genChecksum").checked;
        settings.lineEndingNorm = document.getElementById("lineEndingNorm").checked;
        settings.processingMode = document.getElementById("processingMode").value;
        settings.memLimitMB     = parseInt(document.getElementById("memLimitMB").value)  || 512;
        settings.maxThreads     = parseInt(document.getElementById("maxThreads").value)  || 4;
        settings.batchMode      = document.getElementById("batchMode").value;
        settings.autoVerify     = document.getElementById("autoVerify").checked;
        settings.dryRunMode     = document.getElementById("dryRunMode").checked;
        settings.verboseLog     = document.getElementById("verboseLog").checked;
        settings.diagLog        = document.getElementById("diagLog").checked;
        settings.fileOrder      = document.getElementById("fileOrderSelect").value;
        settings.useStreamSaver = document.getElementById("useStreamSaver").checked;
    } else {
        // These safety/diagnostic settings must always be reset in simple mode
        // so advanced options the user cannot see don't silently affect operation.
        settings.dryRunMode  = false;
        settings.verboseLog  = false;
        settings.diagLog     = false;
        settings.autoVerify  = false;
        settings.batchMode   = "sequential";
    }

    if (!silent) {
        log("Settings applied", "info");
        flash("Settings applied", "success", 2200);
    }
}

// ── Argon2 UI helpers ─────────────────────────────────────────────────

function updateArgon2MemLabel() {
    const kb = parseInt(document.getElementById("argon2Mem").value) || 131072;
    const mb = (kb / 1024).toFixed(0);
    document.getElementById("argon2MemMB").textContent = `(${mb} MB)`;
}

function resetArgon2Defaults() {
    document.getElementById("argon2Mem").value      = ARGON2_MEM_DEFAULT;
    document.getElementById("argon2Time").value     = ARGON2_TIME_DEFAULT;
    document.getElementById("argon2Parallel").value = ARGON2_PARALLEL_LOCAL;
    updateArgon2MemLabel();
    flash("Argon2 parameters reset to defaults", "success", 2000);
}

async function argon2Benchmark() {
    const mem  = parseInt(document.getElementById("argon2Mem").value)     || ARGON2_MEM_DEFAULT;
    const time = parseInt(document.getElementById("argon2Time").value)     || ARGON2_TIME_DEFAULT;
    const par  = parseInt(document.getElementById("argon2Parallel").value) || ARGON2_PARALLEL_LOCAL;
    const pw   = document.getElementById("password").value || "benchmark-test-pw";

    flash("Benchmarking Argon2id… please wait", "info", 0);
    log(`Benchmark: mem=${mem}KB, time=${time}, par=${par}`, "info");
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const t0   = performance.now();
    await argon2.hash({
        pass: pw, salt, time, mem, hashLen: 32,
        parallelism: par, type: argon2.ArgonType.Argon2id
    });
    const elapsed = ((performance.now() - t0) / 1000).toFixed(2);
    flash(`Argon2id: ${elapsed}s with current parameters`, "success", 5000);
    log(`  → KDF took ${elapsed}s`, "success");
}

// ── Salt & nonce controls ─────────────────────────────────────────────

function onDeterministicChange() {
    const en = document.getElementById("deterministicMode").checked;
    document.getElementById("manualSaltRow").classList.toggle("visible", en);
    if (en)
        flash("⚠ Deterministic mode: same inputs → same output. Nonce reuse risk.", "warn", 6000);
}

function genRandomSalt() {
    const arr = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    document.getElementById("manualSalt").value =
        Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ── AAD toggle ────────────────────────────────────────────────────────

function onAADToggle() {
    const en = document.getElementById("useAAD").checked;
    document.getElementById("aadInputRow").classList.toggle("visible", en);
}

// ── Config profiles ───────────────────────────────────────────────────

function buildConfigObject() {
    return {
        version: APP_VERSION,
        simple: {
            nameMode    : settings.nameMode,
            compression : settings.compression,
            chunkSize   : settings.chunkSize,
            keepMeta    : settings.keepMeta,
            encryptMeta : settings.encryptMeta,
            previewMeta : settings.previewMeta,
        },
        advanced: {
            argon2Time         : settings.argon2Time,
            argon2Mem          : settings.argon2Mem,
            argon2Parallel     : settings.argon2Parallel,
            deterministicMode  : settings.deterministicMode,
            useAAD             : settings.useAAD,
            aadString          : settings.aadString,
            containerFormat    : settings.containerFormat,
            genChecksum        : settings.genChecksum,
            lineEndingNorm     : settings.lineEndingNorm,
            processingMode     : settings.processingMode,
            memLimitMB         : settings.memLimitMB,
            maxThreads         : settings.maxThreads,
            batchMode          : settings.batchMode,
            autoVerify         : settings.autoVerify,
            dryRunMode         : settings.dryRunMode,
            verboseLog         : settings.verboseLog,
            diagLog            : settings.diagLog,
            fileOrder          : settings.fileOrder,
            useStreamSaver     : settings.useStreamSaver,
        }
    };
}

function exportConfig() {
    const cfg  = buildConfigObject();
    const json = JSON.stringify(cfg, null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"),
        { href: url, download: "thingtostring-config.json" });
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
    log("Config exported → thingtostring-config.json", "success");
}

function importConfig(event) {
    const f = event.target.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = e => {
        try {
            const cfg = JSON.parse(e.target.result);
            // Compare versions numerically, not as strings.
            // String comparison is lexicographic: "1.9" > "1.20" is true,
            // which would incorrectly flag older patch versions as newer.
            if (cfg.version && parseFloat(cfg.version) > parseFloat(APP_VERSION)) {
                flash(`⚠ Config is from v${cfg.version} — some settings may not apply`, "warn", 6000);
                log(`⚠ Imported config version (${cfg.version}) is newer than app (${APP_VERSION}) — unknown fields ignored`, "warn");
            }
            if (cfg.simple) {
                if (cfg.simple.nameMode)    document.getElementById("nameMode").value = cfg.simple.nameMode;
                if (cfg.simple.compression) document.getElementById("compressionMode").value = cfg.simple.compression;
                if (cfg.simple.chunkSize)   document.getElementById("chunkSizeSelect").value = cfg.simple.chunkSize;
                if (cfg.simple.keepMeta    !== undefined) document.getElementById("keepMeta").checked    = cfg.simple.keepMeta;
                if (cfg.simple.encryptMeta !== undefined) document.getElementById("encryptMeta").checked = cfg.simple.encryptMeta;
                if (cfg.simple.previewMeta !== undefined) document.getElementById("previewMeta").checked = cfg.simple.previewMeta;
            }
            if (cfg.advanced) {
                const a = cfg.advanced;
                if (a.argon2Time)      document.getElementById("argon2Time").value      = a.argon2Time;
                if (a.argon2Mem)     { document.getElementById("argon2Mem").value = a.argon2Mem; updateArgon2MemLabel(); }
                if (a.argon2Parallel)  document.getElementById("argon2Parallel").value  = a.argon2Parallel;
                if (a.deterministicMode !== undefined) {
                    document.getElementById("deterministicMode").checked = a.deterministicMode;
                    onDeterministicChange();
                }
                if (a.useAAD !== undefined) {
                    document.getElementById("useAAD").checked = a.useAAD;
                    onAADToggle();
                }
                if (a.aadString !== undefined) document.getElementById("aadString").value = a.aadString;
                if (a.fileOrder) document.getElementById("fileOrderSelect").value = a.fileOrder;
                if (a.containerFormat) document.getElementById("containerFormat").value = a.containerFormat;
                if (a.batchMode)       document.getElementById("batchMode").value        = a.batchMode;
                if (a.processingMode)  document.getElementById("processingMode").value  = a.processingMode;
                if (a.memLimitMB)      document.getElementById("memLimitMB").value       = a.memLimitMB;
                if (a.maxThreads)      document.getElementById("maxThreads").value       = a.maxThreads;
                if (a.genChecksum    !== undefined) document.getElementById("genChecksum").checked    = a.genChecksum;
                if (a.lineEndingNorm  !== undefined) document.getElementById("lineEndingNorm").checked = a.lineEndingNorm;
                if (a.autoVerify     !== undefined) document.getElementById("autoVerify").checked     = a.autoVerify;
                if (a.dryRunMode     !== undefined) document.getElementById("dryRunMode").checked     = a.dryRunMode;
                if (a.verboseLog     !== undefined) document.getElementById("verboseLog").checked     = a.verboseLog;
                if (a.diagLog        !== undefined) document.getElementById("diagLog").checked        = a.diagLog;
                if (a.useStreamSaver !== undefined) document.getElementById("useStreamSaver").checked = a.useStreamSaver;
            }
            applySettings();
            flash("Config imported successfully", "success", 3000);
        } catch {
            flash("Failed to import config — invalid JSON", "warn", 4000);
        }
    };
    reader.readAsText(f);
    event.target.value = "";
}

function showCLIConfig() {
    const prev = document.getElementById("configPreview");
    if (!prev.classList.contains("config-preview-hidden")) {
        prev.classList.add("config-preview-hidden"); return;
    }
    const cfg = buildConfigObject();
    const lines = [
        `# ThingToString v${APP_VERSION} CLI-compatible config`,
        `--argon2-time     ${cfg.advanced.argon2Time}`,
        `--argon2-mem      ${cfg.advanced.argon2Mem}`,
        `--argon2-parallel ${cfg.advanced.argon2Parallel}`,
        `--compression     ${cfg.simple.compression}`,
        `--chunk-size      ${cfg.simple.chunkSize}`,
        `--name-mode       ${cfg.simple.nameMode}`,
        `--container       ${cfg.advanced.containerFormat}`,
        `--batch-mode      ${cfg.advanced.batchMode}`,
        `--processing-mode ${cfg.advanced.processingMode}`,
        cfg.simple.keepMeta         ? "--keep-meta"       : "--no-meta",
        cfg.simple.encryptMeta      ? "--encrypt-meta"    : "--plain-meta",
        cfg.advanced.autoVerify     ? "--auto-verify"     : "",
        cfg.advanced.dryRunMode     ? "--dry-run"         : "",
        cfg.advanced.genChecksum    ? "--checksum sha256" : "",
        cfg.advanced.deterministicMode ? "--deterministic" : "",
        cfg.advanced.verboseLog     ? "--verbose"         : "",
    ].filter(Boolean).join("\n");
    prev.textContent = lines;
    prev.classList.remove("config-preview-hidden");
}

// ── Reset defaults ────────────────────────────────────────────────────

/**
 * Reset the Simple (Secure) settings panel to defaults, with confirmation.
 */
function resetSimpleDefaults() {
    if (!confirm(
        "Reset Simple (Secure) settings to defaults?\n\n" +
        "• Output name: Original name\n" +
        "• Compression: Standard\n" +
        "• Chunk size: 4 MB\n" +
        "• Include metadata: ON\n" +
        "• Encrypt metadata: ON\n" +
        "• Show metadata preview: OFF\n\n" +
        "This will update the UI and apply immediately."
    )) return;

    document.getElementById("nameMode").value         = "preserve";
    document.getElementById("customName").value       = "";
    document.getElementById("compressionMode").value  = "standard";
    document.getElementById("chunkSizeSelect").value  = "4194304";
    document.getElementById("keepMeta").checked       = true;
    document.getElementById("encryptMeta").checked    = true;
    document.getElementById("previewMeta").checked    = false;
    document.getElementById("decryptNameOverride").value = "";
    onNameModeChange();
    applySettings();
    flash("Simple settings reset to defaults", "success", 2500);
}

/**
 * Reset the Advanced settings panel to defaults, with confirmation.
 * Only available (and callable) when advanced mode is active.
 */
function resetAdvancedDefaults() {
    if (!confirm(
        "Reset Advanced settings to defaults?\n\n" +
        "• Argon2id: mem=128 MB, time=4, parallelism=detected\n" +
        "• Deterministic mode: OFF\n" +
        "• Keyfile: OFF\n" +
        "• AAD: OFF\n" +
        "• Container: Binary\n" +
        "• Checksum, line-ending norm: OFF\n" +
        "• Processing: Streaming, 512 MB limit, 4 threads\n" +
        "• Batch mode: Sequential\n" +
        "• Auto-verify, dry-run, verbose, diag log: OFF\n\n" +
        "This will update the UI and apply immediately."
    )) return;

    // Argon2
    document.getElementById("argon2Time").value               = ARGON2_TIME_DEFAULT;
    document.getElementById("argon2Mem").value                = ARGON2_MEM_DEFAULT;
    document.getElementById("argon2Parallel").value           = ARGON2_PARALLEL_LOCAL;
    // Salt & deterministic
    document.getElementById("deterministicMode").checked      = false;
    document.getElementById("manualSalt").value               = "";
    // Keyfile
    document.getElementById("useKeyfile").checked             = false;
    // AAD
    document.getElementById("useAAD").checked                 = false;
    document.getElementById("aadString").value                = "";
    // Output format
    document.getElementById("containerFormat").value          = "binary";
    document.getElementById("genChecksum").checked            = false;
    document.getElementById("lineEndingNorm").checked         = false;
    // Performance
    document.getElementById("processingMode").value           = "streaming";
    document.getElementById("memLimitMB").value               = 512;
    document.getElementById("maxThreads").value               = 4;
    document.getElementById("batchMode").value                = "sequential";
    // Safety
    document.getElementById("autoVerify").checked             = false;
    document.getElementById("dryRunMode").checked             = false;
    document.getElementById("verboseLog").checked             = false;
    document.getElementById("diagLog").checked                = false;
    document.getElementById("useStreamSaver").checked         = true;

    // Re-fire dependent UI toggles
    onDeterministicChange();
    onKeyfileToggle();
    onAADToggle();
    updateArgon2MemLabel();
    applySettings();
    flash("Advanced settings reset to defaults", "success", 2500);
}

// ── Event wiring moved to init.js ────────────────────────────────────
// (All addEventListener calls are centralised there.)

