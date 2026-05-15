// ═══════════════════════════════════════════════════════════════════
// init.js  —  Wires every event listener and runs startup.
//             No inline handlers exist in index.html — they all live
//             here so the CSP can be enforced as script-src 'self'.
//
//             Load order: must be last (after all other JS files).
// ═══════════════════════════════════════════════════════════════════
"use strict";

document.addEventListener("DOMContentLoaded", function () {

    // ── Stamp version from the single source of truth ─────────────────
    document.getElementById("appVersionLabel").textContent = "v" + APP_VERSION;
    document.title = "ThingToString v" + APP_VERSION;
    document.getElementById("hwConcurrency").textContent =
        navigator.hardwareConcurrency || "unknown";

    // ── Flash close button ────────────────────────────────────────────
    document.getElementById("btnFlashClose").addEventListener("click", function () {
        document.getElementById("flashBanner").style.display = "none";
    });

    // ── Header: mode toggle ───────────────────────────────────────────
    document.getElementById("modeToggle").addEventListener("click", function() { toggleMode(); });

    // ── Header: theme switcher (event delegation on parent) ───────────
    document.querySelector(".theme-switcher").addEventListener("click", function (e) {
        const opt = e.target.closest(".theme-opt");
        if (opt && opt.dataset.themeVal) setTheme(opt.dataset.themeVal);
    });

    // ── Expand-toggle: any element with data-expand wires up here ─────
    document.querySelectorAll(".expand-toggle[data-expand]").forEach(function (el) {
        el.addEventListener("click", function () {
            toggleExpand(el.dataset.expand);
        });
    });

    // ── File inputs & drop zone ───────────────────────────────────────
    document.getElementById("fileInput").addEventListener("change", function (e) {
        addFiles(e.target.files); e.target.value = "";
    });
    document.getElementById("folderInput").addEventListener("change", function (e) {
        addFiles(e.target.files); e.target.value = "";
    });

    var dz = document.getElementById("dropZone");
    dz.addEventListener("dragover",  function (e) { e.preventDefault(); dz.classList.add("drag"); });
    dz.addEventListener("dragleave", function ()  { dz.classList.remove("drag"); });
    dz.addEventListener("drop",      function (e) {
        e.preventDefault(); dz.classList.remove("drag");
        addFiles(e.dataTransfer.files);
    });
    dz.addEventListener("click", function () { document.getElementById("fileInput").click(); });

    document.getElementById("btnRemoveSelected").addEventListener("click", function () { removeSelected(); });
    document.getElementById("btnClearQueue").addEventListener("click", function () { clearQueue(); });
    document.getElementById("fileOrderSelect").addEventListener("change", function () { applyFileOrder(); });

    // ── Password ──────────────────────────────────────────────────────
    document.getElementById("password").addEventListener("input", function () {
        checkPasswordStrength();
        checkConfirmMatch();
    });
    document.getElementById("passwordConfirm").addEventListener("input", function () { checkConfirmMatch(); });
    document.getElementById("btnShowPassword").addEventListener("click", function () { toggleShowPassword(); });
    document.getElementById("btnShowConfirm").addEventListener("click", function () { toggleShowConfirm(); });

    // ── Passphrase generator ──────────────────────────────────────────
    document.getElementById("btnGeneratePassphrase").addEventListener("click", function () { generatePassphrase(); });
    document.getElementById("btnCopyPassphrase").addEventListener("click", function () { copyPassphrase(); });
    document.getElementById("btnUsePassphrase").addEventListener("click", function () { usePassphrase(); });

    // ── Keyfile ───────────────────────────────────────────────────────
    document.getElementById("useKeyfile").addEventListener("change", function () { onKeyfileToggle(); });
    document.getElementById("keyfileInput").addEventListener("change", function () { onKeyfileSelected(); });
    document.getElementById("btnClearKeyfile").addEventListener("click", function () { clearKeyfile(); });

    // ── Name mode ─────────────────────────────────────────────────────
    document.getElementById("nameMode").addEventListener("change", function () { onNameModeChange(); });

    // ── Argon2 ───────────────────────────────────────────────────────
    document.getElementById("argon2Mem").addEventListener("input", function () { updateArgon2MemLabel(); });
    document.getElementById("btnResetArgon2").addEventListener("click", function () { resetArgon2Defaults(); });
    document.getElementById("btnBenchmark").addEventListener("click", function () { argon2Benchmark(); });

    // ── Salt / deterministic ──────────────────────────────────────────
    document.getElementById("deterministicMode").addEventListener("change", function () { onDeterministicChange(); });
    document.getElementById("btnGenSalt").addEventListener("click", function () { genRandomSalt(); });

    // ── AAD ───────────────────────────────────────────────────────────
    document.getElementById("useAAD").addEventListener("change", function () { onAADToggle(); });

    // ── Config profiles ───────────────────────────────────────────────
    document.getElementById("btnExportConfig").addEventListener("click", function () { exportConfig(); });
    document.getElementById("importConfigInput").addEventListener("change", function (e) { importConfig(e); });
    document.getElementById("btnShowCLI").addEventListener("click", function () { showCLIConfig(); });

    // ── Apply settings ────────────────────────────────────────────────
    document.getElementById("btnApplySettings").addEventListener("click", function () { applySettings(); });

    // ── Reset defaults ────────────────────────────────────────────────
    document.getElementById("btnResetSimpleDefaults").addEventListener("click", function () { resetSimpleDefaults(); });
    document.getElementById("btnResetAdvancedDefaults").addEventListener("click", function () { resetAdvancedDefaults(); });

    // ── Actions ───────────────────────────────────────────────────────
    document.getElementById("btnEncrypt").addEventListener("click", function () {
        processQueue("encrypt");
    });
    document.getElementById("btnDecrypt").addEventListener("click", function () {
        processQueue("decrypt");
    });
    document.getElementById("cancelBtn").addEventListener("click", function () { cancelProcess(); });

    // ── Log ───────────────────────────────────────────────────────────
    document.getElementById("btnClearLog").addEventListener("click", function () { clearLog(); });

    // ── Modal ─────────────────────────────────────────────────────────
    document.getElementById("btnMetaCancel").addEventListener("click",  function () { closeMetaModal(false); });
    document.getElementById("btnMetaProceed").addEventListener("click", function () { closeMetaModal(true); });

    // ── Auto-apply settings so state matches UI on first load ─────────
    applySettings(true);
    updateArgon2MemLabel();

    flash("v" + APP_VERSION + " ready.", "success", 3000);
});
