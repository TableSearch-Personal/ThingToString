// ═══════════════════════════════════════════════════════════════════
// settings.js  —  Settings panel: read/apply UI values, Argon2 UI
//                 helpers, salt/nonce controls, AAD toggle, and
//                 config profile import/export
// ═══════════════════════════════════════════════════════════════════
"use strict";

// ── Name-mode toggle ─────────────────────────────────────────────────

function onNameModeChange() {
    const mode = document.getElementById("nameMode").value;
    document.getElementById("customName").style.display = mode === "custom" ? "" : "none";
}

// ── Apply settings from UI to state object ───────────────────────────

function applySettings() {
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
        settings.versionPin     = document.getElementById("versionPin").value;
        settings.processingMode = document.getElementById("processingMode").value;
        settings.memLimitMB     = parseInt(document.getElementById("memLimitMB").value)  || 512;
        settings.maxThreads     = parseInt(document.getElementById("maxThreads").value)  || 4;
        settings.batchMode      = document.getElementById("batchMode").value;
        settings.autoVerify     = document.getElementById("autoVerify").checked;
        settings.dryRunMode     = document.getElementById("dryRunMode").checked;
        settings.verboseLog     = document.getElementById("verboseLog").checked;
        settings.fileOrder      = document.getElementById("fileOrderSelect").value;
    }

    log("Settings applied", "info");
    flash("Settings applied", "success", 2200);
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
    document.getElementById("manualSaltRow").style.display = en ? "" : "none";
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
    document.getElementById("aadInputRow").style.display = en ? "" : "none";
}

// ── Config profiles ───────────────────────────────────────────────────

function buildConfigObject() {
    return {
        version: "1.18",
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
            versionPin         : settings.versionPin,
            processingMode     : settings.processingMode,
            memLimitMB         : settings.memLimitMB,
            maxThreads         : settings.maxThreads,
            batchMode          : settings.batchMode,
            autoVerify         : settings.autoVerify,
            dryRunMode         : settings.dryRunMode,
            verboseLog         : settings.verboseLog,
            fileOrder          : settings.fileOrder,
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
    if (prev.style.display !== "none") { prev.style.display = "none"; return; }
    const cfg = buildConfigObject();
    const lines = [
        "# ThingToString v1.18 CLI-compatible config",
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
    prev.style.display = "";
}

// ── Wire up Argon2 memory label on DOMContentLoaded ──────────────────

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("argon2Mem").addEventListener("input", updateArgon2MemLabel);
});
