// ═══════════════════════════════════════════════════════════════════
// password.js  —  Password strength, validation, confirm matching,
//                 passphrase generator, and keyfile handling
// ═══════════════════════════════════════════════════════════════════
"use strict";

// ── Strength indicator ───────────────────────────────────────────────

function checkPasswordStrength() {
    const pw = document.getElementById("password").value;
    const el = document.getElementById("passwordStrength");
    if (!pw) { el.textContent = ""; el.style.color = ""; return; }
    let score = 0;
    if (pw.length >= MIN_PASSWORD_LEN) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    const levels = [
        { label: "Very weak",   color: "#cc2020" },
        { label: "Weak",        color: "#d05000" },
        { label: "Fair",        color: "#c08000" },
        { label: "Strong",      color: "#80c000" },
        { label: "Very strong", color: "#00c060" },
        { label: "Excellent",   color: "#00e8a0" },
    ];
    const lvl = levels[Math.min(score, levels.length - 1)];
    el.textContent = lvl.label;
    el.style.color = lvl.color;
}

function validatePassword(pw) {
    if (!pw) throw new TSFError("validation", "Password is required");
    if (pw.length < MIN_PASSWORD_LEN)
        throw new TSFError("validation", `Password too short — minimum ${MIN_PASSWORD_LEN} characters`);
}

// ── Confirm field ────────────────────────────────────────────────────

function checkConfirmMatch() {
    const pw  = document.getElementById("password").value;
    const cpw = document.getElementById("passwordConfirm").value;
    const msg = document.getElementById("confirmMatchMsg");
    if (!cpw) { msg.textContent = ""; msg.className = ""; return; }
    if (pw === cpw) {
        msg.textContent = "✓ Match";
        msg.className   = "match";
    } else {
        msg.textContent = "✗ No match";
        msg.className   = "nomatch";
    }
}

// ── Show/hide toggles ────────────────────────────────────────────────

function toggleShowPassword() {
    const el = document.getElementById("password");
    el.type = el.type === "password" ? "text" : "password";
    const ec = document.getElementById("passwordConfirm");
    if (ec) ec.type = el.type;
}

function toggleShowConfirm() {
    const el = document.getElementById("passwordConfirm");
    el.type = el.type === "password" ? "text" : "password";
}

// ── Passphrase generator ─────────────────────────────────────────────

const PP_WORDS = [
    "anchor","barrel","canyon","diesel","empire","fender","gravel","harbor",
    "island","jacket","kettle","lancer","magnet","nebula","onward","pillar",
    "quartz","riddle","signal","timber","upturn","valley","wander","xenon",
    "yellow","zenith","alpine","bronze","castle","dragon","engine","falcon",
    "glacial","hunter","inline","jungle","kitten","legend","marble","nimble",
    "oracle","ponder","quorum","rescue","silver","tunnel","unique","vendor",
    "winter","oxygen","mirror","lantern","forest","cobalt","beacon","arctic"
];

function generatePassphrase() {
    const n   = Math.max(4, Math.min(20, parseInt(document.getElementById("ppWords").value) || 6));
    const sep = document.getElementById("ppSep").value;
    const arr = new Uint32Array(n);
    crypto.getRandomValues(arr);
    const words = Array.from(arr).map(v => PP_WORDS[v % PP_WORDS.length]);
    document.getElementById("ppOutput").textContent = words.join(sep);
}

function copyPassphrase() {
    const txt = document.getElementById("ppOutput").textContent;
    if (txt === "Click Generate…") return;
    navigator.clipboard.writeText(txt).then(() => flash("Copied to clipboard", "success", 1500));
}

function usePassphrase() {
    const txt = document.getElementById("ppOutput").textContent;
    if (txt === "Click Generate…") return;
    document.getElementById("password").value = txt;
    document.getElementById("passwordConfirm").value = txt;
    checkPasswordStrength();
    checkConfirmMatch();
    flash("Passphrase set as password — confirm field also filled", "success", 2500);
}

// ── Keyfile handling ─────────────────────────────────────────────────

function onKeyfileToggle() {
    const en = document.getElementById("useKeyfile").checked;
    document.getElementById("keyfilePickRow").style.display = en ? "" : "none";
    if (!en) clearKeyfile();
}

function onKeyfileSelected() {
    const f = document.getElementById("keyfileInput").files[0];
    if (!f) return;
    if (f.size > 16 * 1024 * 1024) {
        flash("Keyfile too large (max 16 MB)", "warn"); return;
    }
    f.arrayBuffer().then(buf => {
        keyfileData = new Uint8Array(buf);
        document.getElementById("keyfileName").textContent = `${f.name} (${formatSize(f.size)})`;
        log(`Keyfile loaded: ${escapeHtml(f.name)} (${formatSize(f.size)})`, "info");
    });
}

function clearKeyfile() {
    keyfileData = null;
    document.getElementById("keyfileInput").value = "";
    document.getElementById("keyfileName").textContent = "No keyfile selected";
}
