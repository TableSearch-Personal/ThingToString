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

function clearLog() { document.getElementById("log").innerHTML = ""; }

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

function toggleMode() {
    isAdvancedMode = !isAdvancedMode;
    document.body.classList.toggle("advanced-mode", isAdvancedMode);
    document.getElementById("modeSimple").classList.toggle("active", !isAdvancedMode);
    document.getElementById("modeAdv").classList.toggle("active",  isAdvancedMode);
    if (isAdvancedMode) {
        flash("Advanced mode enabled — additional controls are now visible in Settings.", "info", 4000);
        document.getElementById("hwConcurrency").textContent =
            navigator.hardwareConcurrency || "unknown";
        updateArgon2MemLabel();
    } else {
        flash("Simple mode — using secure defaults.", "info", 2500);
    }
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
        table.innerHTML = "";
        const rows = [
            ["Original name", meta.originalName  || "(hidden / none)"],
            ["MIME type",     meta.mimeType       || "(unknown)"],
            ["Compression",   meta.compression    || "(unknown)"],
            ["Created",       meta.created ? new Date(meta.created).toLocaleString() : "(unknown)"],
            ["Name mode",     meta.nameMode       || "(unknown)"],
        ];
        for (const [k, v] of rows) {
            const tr = document.createElement("tr");
            tr.innerHTML = `<td>${escapeHtml(k)}</td><td>${escapeHtml(String(v))}</td>`;
            table.appendChild(tr);
        }
        document.getElementById("metaModal").classList.add("open");
    });
}

function closeMetaModal(proceed) {
    document.getElementById("metaModal").classList.remove("open");
    if (_metaModalResolve) { _metaModalResolve(proceed); _metaModalResolve = null; }
}
