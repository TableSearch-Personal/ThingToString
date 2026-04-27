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
        const dup = queue.some(x =>
            x.name === f.name && x.size === f.size && x.lastModified === f.lastModified);
        if (!dup) { queue.push(f); if (f.size > MAX_FILE_SIZE) oversized++; }
    }
    if (skipped > 0)
        log(`⚠ ${skipped} file(s) skipped — queue limit (${MAX_QUEUE_SIZE}) reached`, "warn");
    const banner = document.getElementById("sizeLimitBanner");
    if (oversized > 0) {
        banner.textContent =
            `ℹ ${oversized} file(s) exceed ${MAX_FILE_SIZE / 1024 / 1024} MB — streamed chunk-by-chunk (low RAM usage).`;
        banner.style.display = "";
    } else {
        banner.style.display = "none";
    }
    applyFileOrder();
}

function applyFileOrder() {
    if (!isAdvancedMode) { renderQueue(); return; }
    const mode = document.getElementById("fileOrderSelect").value;
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
    list.innerHTML = "";
    if (!queue.length) {
        list.innerHTML = '<div class="empty">No files added</div>';
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
            row.draggable = true;
            row.dataset.index = i;
            row.addEventListener("dragstart", onDragStart);
            row.addEventListener("dragover",  onDragOver);
            row.addEventListener("drop",      onDragDrop);
            row.addEventListener("dragend",   onDragEnd);
        }
        const warn = f.size > MAX_FILE_SIZE
            ? ' <span title="Large file — streamed" style="color:#c08020">📦</span>' : "";
        row.innerHTML = `
            ${manualDrag ? '<span class="drag-handle" title="Drag to reorder">⠿</span>' : ""}
            <label>
                <input type="checkbox" data-index="${i}">
                <span class="fname">${escapeHtml(f.name)}${warn}</span>
            </label>
            <span class="fsize">${formatSize(f.size)}</span>`;
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

// ── Drop-zone & file input wiring  (runs after DOM is ready) ─────────

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("fileInput").addEventListener("change", e => {
        addFiles(e.target.files); e.target.value = "";
    });
    document.getElementById("folderInput").addEventListener("change", e => {
        addFiles(e.target.files); e.target.value = "";
    });

    const dz = document.getElementById("dropZone");
    dz.addEventListener("dragover",  e => { e.preventDefault(); dz.classList.add("drag"); });
    dz.addEventListener("dragleave", ()  => dz.classList.remove("drag"));
    dz.addEventListener("drop", e => {
        e.preventDefault(); dz.classList.remove("drag");
        addFiles(e.dataTransfer.files);
    });
    dz.addEventListener("click", () => document.getElementById("fileInput").click());
});
