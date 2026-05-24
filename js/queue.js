// ═══════════════════════════════════════════════════════════════════
// queue.js  —  File queue: add, remove, order, render, drag-reorder,
//              and drop-zone wiring
// ═══════════════════════════════════════════════════════════════════
"use strict";

// ── Helpers ──────────────────────────────────────────────────────────

function formatSize(bytes) {
    if (bytes >= 1024 * 1024) return (bytes / 1024 / 1024).toFixed(2) + " MB";
    if (bytes >= 1024)        return (bytes / 1024).toFixed(1) + " KB";
    return bytes + " B";
}

function escapeHtml(s) {
    return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ── Queue management ─────────────────────────────────────────────────

function addFiles(files) {
    let skipped = 0, oversized = 0;
    for (const f of files) {
        if (queue.length >= MAX_QUEUE_SIZE) { skipped++; continue; }
        // lastModified is 0 for File objects created with `new File([blob], name)`
        // (e.g. after Base64 decode in decryptFile), making it unreliable as a
        // uniqueness signal. We treat lastModified===0 as "unknown" and fall back
        // to name+size only for those files, accepting the small false-positive
        // risk rather than silently dropping legitimately distinct files.
        const dup = queue.some(x => {
            if (x.name !== f.name || x.size !== f.size) return false;
            if (f.lastModified === 0 || x.lastModified === 0) return true;
            return x.lastModified === f.lastModified;
        });
        if (!dup) { queue.push(f); if (f.size > LARGE_FILE_THRESHOLD) oversized++; }
    }
    if (skipped > 0)
        log(`⚠ ${skipped} file(s) skipped — queue limit (${MAX_QUEUE_SIZE}) reached`, "warn");
    const banner = document.getElementById("sizeLimitBanner");
    if (oversized > 0) {
        banner.textContent =
            `ℹ ${oversized} large file(s) (>2 GB) — processed chunk-by-chunk with minimal RAM usage.`;
        banner.style.display = "";
    } else {
        banner.style.display = "none";
    }
    applyFileOrder();
}

function applyFileOrder() {
    const select = document.getElementById("fileOrderSelect");
    const mode   = select ? select.value : currentFileOrder;
    currentFileOrder = mode;
    if      (mode === "name-asc")  queue.sort((a, b) => a.name.localeCompare(b.name));
    else if (mode === "name-desc") queue.sort((a, b) => b.name.localeCompare(a.name));
    else if (mode === "size-asc")  queue.sort((a, b) => a.size - b.size);
    else if (mode === "size-desc") queue.sort((a, b) => b.size - a.size);
    renderQueue();
}

function removeSelected() {
    const sel = [...document.querySelectorAll("#fileList input:checked")]
        .map(x => parseInt(x.dataset.index));
    queue = queue.filter((_, i) => !sel.includes(i));
    renderQueue();
}

function clearQueue() {
    queue = [];
    document.getElementById("sizeLimitBanner").style.display = "none";
    renderQueue();
}

// ── Render ───────────────────────────────────────────────────────────

function renderQueue() {
    const list = document.getElementById("fileList");
    // Clear safely with DOM methods (no innerHTML on user data)
    while (list.firstChild) list.removeChild(list.firstChild);

    if (!queue.length) {
        const empty = document.createElement("div");
        empty.className   = "empty";
        empty.textContent = "No files added";
        list.appendChild(empty);
        document.getElementById("queueInfo").textContent = "";
        return;
    }

    const totalBytes = queue.reduce((s, f) => s + f.size, 0);
    document.getElementById("queueInfo").textContent =
        `${queue.length} file(s) · ${formatSize(totalBytes)}`;

    const manualDrag = isAdvancedMode && currentFileOrder === "manual";

    queue.forEach((f, i) => {
        const row = document.createElement("div");
        row.className = "fileItem";

        if (manualDrag) {
            row.draggable    = true;
            row.dataset.index = i;
            row.addEventListener("dragstart", onDragStart);
            row.addEventListener("dragover",  onDragOver);
            row.addEventListener("drop",      onDragDrop);
            row.addEventListener("dragend",   onDragEnd);

            const handle = document.createElement("span");
            handle.className = "drag-handle";
            handle.title     = "Drag to reorder";
            handle.textContent = "⠿";
            row.appendChild(handle);
        }

        const label = document.createElement("label");
        const cb    = document.createElement("input");
        cb.type              = "checkbox";
        cb.dataset.index     = i;
        label.appendChild(cb);

        const fname = document.createElement("span");
        fname.className  = "fname";
        fname.textContent = f.name;   // textContent — fully safe, no escaping needed
        label.appendChild(fname);

        if (f.size > LARGE_FILE_THRESHOLD) {
            const warn = document.createElement("span");
            warn.title       = "Large file — streamed";
            warn.style.color = "#c08020";
            warn.textContent = " 📦";
            label.appendChild(warn);
        }

        const fsize = document.createElement("span");
        fsize.className  = "fsize";
        fsize.textContent = formatSize(f.size);

        row.appendChild(label);
        row.appendChild(fsize);
        list.appendChild(row);
    });
}

// ── Drag-to-reorder ──────────────────────────────────────────────────

function onDragStart(e) {
    dragSrcIndex = parseInt(e.currentTarget.dataset.index);
    e.currentTarget.classList.add("dragging");
}

function onDragOver(e) {
    e.preventDefault();
    document.querySelectorAll(".fileItem.drag-over")
        .forEach(el => el.classList.remove("drag-over"));
    e.currentTarget.classList.add("drag-over");
}

function onDragDrop(e) {
    e.preventDefault();
    const target = parseInt(e.currentTarget.dataset.index);
    if (dragSrcIndex !== null && dragSrcIndex !== target) {
        const [moved] = queue.splice(dragSrcIndex, 1);
        queue.splice(target, 0, moved);
        renderQueue();
    }
}

function onDragEnd(e) {
    e.currentTarget.classList.remove("dragging");
    document.querySelectorAll(".fileItem.drag-over")
        .forEach(el => el.classList.remove("drag-over"));
    dragSrcIndex = null;
}

// ── Drop-zone & file input wiring moved to init.js ──────────────────
// (All addEventListener calls are centralised there.)

