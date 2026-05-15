// ═══════════════════════════════════════════════════════════════════
// ui.js  —  UI helpers: logging, progress, flash banner, theme,
//            mode toggle, expand/collapse, and modal
// ═══════════════════════════════════════════════════════════════════
"use strict";

// ── Logging ─────────────────────────────────────────────────────────

function log(msg, level = "success") {
    const box  = document.getElementById("log");
    const span = document.createElement("span");
    span.className   = "log-" + level;
    span.textContent = msg + "\n";
    box.appendChild(span);
    box.scrollTop = box.scrollHeight;
}

function logSep() { log("─────────────────────────────────────────", "dim"); }

function clearLog() {
    const box = document.getElementById("log");
    while (box.firstChild) box.removeChild(box.firstChild);
}

/** Only logs when verboseLog is on, unless it's an error/warn/success. */
function logV(msg, level = "info") {
    if (settings.verboseLog || level === "error" || level === "warn" || level === "success")
        log(msg, level);
}

// ── Progress bar ─────────────────────────────────────────────────────

function updateProgress(percent, label = "") {
    document.getElementById("progressFill").style.width  = percent + "%";
    document.getElementById("progressLabel").textContent = label;
}

function etaString(elapsedMs, fraction) {
    if (fraction <= 0 || fraction >= 1) return "";
    const secs = Math.round((elapsedMs / fraction) * (1 - fraction) / 1000);
    if (secs < 5)  return "< 5 s";
    if (secs < 60) return `~${secs} s`;
    return `~${Math.floor(secs / 60)} min ${secs % 60} s`;
}

// ── Flash banner ─────────────────────────────────────────────────────

function flash(msg, type = "info", durationMs = 3000) {
    const el = document.getElementById("flashBanner");
    el.className = "flash-banner " + type;
    document.getElementById("flashMsg").textContent = msg;
    el.style.display = "flex";
    if (durationMs > 0) setTimeout(() => { el.style.display = "none"; }, durationMs);
}

// ── Theme switcher ───────────────────────────────────────────────────

function setTheme(theme) {
    currentTheme = theme;
    const root = document.documentElement;
    if (theme === "dark") {
        root.removeAttribute("data-theme");
    } else {
        root.setAttribute("data-theme", theme);
    }
    document.querySelectorAll(".theme-opt").forEach(el => {
        el.classList.toggle("active", el.dataset.themeVal === theme);
    });
    const labels = { dark: "Dark theme", darker: "Darker theme", contrast: "High Contrast theme" };
    flash(labels[theme] + " active", "info", 2000);
}

// ── Simple / Advanced mode toggle ────────────────────────────────────
//
// Each mode keeps its own in-memory UI snapshot so that switching modes
// is lossless: go Advanced → Simple → Advanced and your advanced settings
// are exactly as you left them.  No localStorage is used.
//
// _modeSnapshot["simple"]   — last known simple-mode UI values
// _modeSnapshot["advanced"] — last known advanced-mode UI values
// Both start as null (no snapshot yet) and are populated on first departure.

const _modeSnapshot = { simple: null, advanced: null };

/** Read every settings UI field into a plain object. */
function _captureUISnapshot() {
    const snap = {
        // Simple fields
        nameMode            : document.getElementById("nameMode").value,
        customName          : document.getElementById("customName").value,
        compressionMode     : document.getElementById("compressionMode").value,
        keepMeta            : document.getElementById("keepMeta").checked,
        encryptMeta         : document.getElementById("encryptMeta").checked,
        chunkSizeSelect     : document.getElementById("chunkSizeSelect").value,
        decryptNameOverride : document.getElementById("decryptNameOverride").value,
        previewMeta         : document.getElementById("previewMeta").checked,
        // Advanced fields
        argon2Time          : document.getElementById("argon2Time").value,
        argon2Mem           : document.getElementById("argon2Mem").value,
        argon2Parallel      : document.getElementById("argon2Parallel").value,
        deterministicMode   : document.getElementById("deterministicMode").checked,
        manualSalt          : document.getElementById("manualSalt").value,
        useKeyfile          : document.getElementById("useKeyfile").checked,
        useAAD              : document.getElementById("useAAD").checked,
        aadString           : document.getElementById("aadString").value,
        containerFormat     : document.getElementById("containerFormat").value,
        genChecksum         : document.getElementById("genChecksum").checked,
        lineEndingNorm      : document.getElementById("lineEndingNorm").checked,
        processingMode      : document.getElementById("processingMode").value,
        memLimitMB          : document.getElementById("memLimitMB").value,
        maxThreads          : document.getElementById("maxThreads").value,
        batchMode           : document.getElementById("batchMode").value,
        autoVerify          : document.getElementById("autoVerify").checked,
        dryRunMode          : document.getElementById("dryRunMode").checked,
        verboseLog          : document.getElementById("verboseLog").checked,
        fileOrderSelect     : document.getElementById("fileOrderSelect").value,
    };
    return snap;
}

/** Write a snapshot back into the UI fields. */
function _restoreUISnapshot(snap) {
    document.getElementById("nameMode").value                 = snap.nameMode;
    document.getElementById("customName").value               = snap.customName;
    document.getElementById("compressionMode").value          = snap.compressionMode;
    document.getElementById("keepMeta").checked               = snap.keepMeta;
    document.getElementById("encryptMeta").checked            = snap.encryptMeta;
    document.getElementById("chunkSizeSelect").value          = snap.chunkSizeSelect;
    document.getElementById("decryptNameOverride").value      = snap.decryptNameOverride;
    document.getElementById("previewMeta").checked            = snap.previewMeta;
    document.getElementById("argon2Time").value               = snap.argon2Time;
    document.getElementById("argon2Mem").value                = snap.argon2Mem;
    document.getElementById("argon2Parallel").value           = snap.argon2Parallel;
    document.getElementById("deterministicMode").checked      = snap.deterministicMode;
    document.getElementById("manualSalt").value               = snap.manualSalt;
    document.getElementById("useKeyfile").checked             = snap.useKeyfile;
    document.getElementById("useAAD").checked                 = snap.useAAD;
    document.getElementById("aadString").value                = snap.aadString;
    document.getElementById("containerFormat").value          = snap.containerFormat;
    document.getElementById("genChecksum").checked            = snap.genChecksum;
    document.getElementById("lineEndingNorm").checked         = snap.lineEndingNorm;
    document.getElementById("processingMode").value           = snap.processingMode;
    document.getElementById("memLimitMB").value               = snap.memLimitMB;
    document.getElementById("maxThreads").value               = snap.maxThreads;
    document.getElementById("batchMode").value                = snap.batchMode;
    document.getElementById("autoVerify").checked             = snap.autoVerify;
    document.getElementById("dryRunMode").checked             = snap.dryRunMode;
    document.getElementById("verboseLog").checked             = snap.verboseLog;
    document.getElementById("fileOrderSelect").value          = snap.fileOrderSelect;
    // Re-fire dependent UI updates so conditional rows show/hide correctly
    onNameModeChange();
    onDeterministicChange();
    onKeyfileToggle();
    onAADToggle();
    updateArgon2MemLabel();
}

/** Secure defaults applied to the UI whenever entering Simple mode for the first time. */
function _applySecureDefaults() {
    document.getElementById("argon2Time").value               = ARGON2_TIME_DEFAULT;
    document.getElementById("argon2Mem").value                = ARGON2_MEM_DEFAULT;
    document.getElementById("argon2Parallel").value           = ARGON2_PARALLEL_LOCAL;
    document.getElementById("deterministicMode").checked      = false;
    document.getElementById("manualSalt").value               = "";
    document.getElementById("useKeyfile").checked             = false;
    document.getElementById("useAAD").checked                 = false;
    document.getElementById("aadString").value                = "";
    document.getElementById("containerFormat").value          = "binary";
    document.getElementById("genChecksum").checked            = false;
    document.getElementById("lineEndingNorm").checked         = false;
    document.getElementById("processingMode").value           = "streaming";
    document.getElementById("memLimitMB").value               = 512;
    document.getElementById("maxThreads").value               = 4;
    document.getElementById("batchMode").value                = "sequential";
    document.getElementById("autoVerify").checked             = false;
    document.getElementById("dryRunMode").checked             = false;
    document.getElementById("verboseLog").checked             = false;
    onDeterministicChange();
    onKeyfileToggle();
    onAADToggle();
    updateArgon2MemLabel();
}

function toggleMode() {
    const leavingMode  = isAdvancedMode ? "advanced" : "simple";
    const arrivingMode = isAdvancedMode ? "simple"   : "advanced";

    // Save the current UI state for the mode we are leaving
    _modeSnapshot[leavingMode] = _captureUISnapshot();

    isAdvancedMode = !isAdvancedMode;
    document.body.classList.toggle("advanced-mode", isAdvancedMode);
    document.getElementById("modeSimple").classList.toggle("active", !isAdvancedMode);
    document.getElementById("modeAdv").classList.toggle("active",  isAdvancedMode);

    if (_modeSnapshot[arrivingMode]) {
        // We have been here before — restore exactly what the user left
        _restoreUISnapshot(_modeSnapshot[arrivingMode]);
    } else if (arrivingMode === "simple") {
        // First visit to Simple mode — enforce secure defaults
        _applySecureDefaults();
    }
    // First visit to Advanced mode needs no special treatment —
    // the UI already shows the current values which are already safe defaults.

    if (isAdvancedMode) {
        document.getElementById("hwConcurrency").textContent =
            navigator.hardwareConcurrency || "unknown";
        flash("Advanced mode — additional controls visible in Settings.", "info", 4000);
    } else {
        flash("Simple mode — secure defaults applied.", "info", 2500);
    }

    // Silently sync the settings object to match the restored/defaulted UI
    applySettings(true);
}

// ── Expandable sections ──────────────────────────────────────────────

function toggleExpand(id) {
    const body  = document.getElementById(id);
    const caret = document.getElementById("caret" + id.charAt(0).toUpperCase() + id.slice(1));
    const open  = body.classList.toggle("open");
    if (caret) caret.classList.toggle("open", open);
}

// ── Metadata preview modal ───────────────────────────────────────────

function showMetaModal(meta) {
    return new Promise(resolve => {
        _metaModalResolve = resolve;
        const table = document.getElementById("metaTable");
        while (table.firstChild) table.removeChild(table.firstChild);
        const rows = [
            ["Original name", meta.originalName  || "(hidden / none)"],
            ["MIME type",     meta.mimeType       || "(unknown)"],
            ["Compression",   meta.compression    || "(unknown)"],
            ["Created",       meta.created ? new Date(meta.created).toLocaleString() : "(unknown)"],
            ["Name mode",     meta.nameMode       || "(unknown)"],
        ];
        for (const [k, v] of rows) {
            const tr  = document.createElement("tr");
            const td1 = document.createElement("td");
            const td2 = document.createElement("td");
            td1.textContent = k;
            td2.textContent = String(v);
            tr.appendChild(td1);
            tr.appendChild(td2);
            table.appendChild(tr);
        }
        document.getElementById("metaModal").classList.add("open");
    });
}

function closeMetaModal(proceed) {
    document.getElementById("metaModal").classList.remove("open");
    if (_metaModalResolve) { _metaModalResolve(proceed); _metaModalResolve = null; }
}
