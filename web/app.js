/**
 * app.js — RTR Script Lab
 *
 * Wires together:
 *  • Sidebar script browser (search + phase filter)
 *  • Monaco editor (PowerShell syntax, dark theme)
 *  • Info panel (metadata, usage, checklist)
 *  • Header actions (copy, download, reset)
 */

/* ═══════════════════════════════════════════════════════ STATE ══════════ */
let editor       = null;   // Monaco editor instance
let currentScript = null;  // Currently loaded script object
let originalSrc   = "";    // Original source (for reset + dirty detection)
let activeFilter  = "all"; // Current IR phase filter

/* ═══════════════════════════════════════════════════════ SIDEBAR ════════ */

const CATEGORIES = ["Triage", "Process Investigation", "Artefact Collection", "Remediation"];

function renderSidebar(filter = "all", query = "") {
  const nav = document.getElementById("script-nav");
  nav.innerHTML = "";
  const q = query.toLowerCase();

  CATEGORIES.forEach(cat => {
    const scripts = window.RTR_SCRIPTS.filter(s => {
      const matchesCat   = s.category === cat;
      const matchesPhase = filter === "all" || s.irPhase.includes(filter);
      const matchesQuery = !q || s.name.toLowerCase().includes(q) || s.shortDesc.toLowerCase().includes(q);
      return matchesCat && matchesPhase && matchesQuery;
    });

    if (scripts.length === 0) return;

    const label = document.createElement("div");
    label.className = "nav-group-label";
    label.textContent = cat;
    nav.appendChild(label);

    scripts.forEach(s => {
      const item = document.createElement("div");
      item.className = "nav-item" + (currentScript?.id === s.id ? " active" : "");
      item.dataset.id = s.id;

      // Phase indicator dot — multi-phase scripts get the blended style
      const phases = s.irPhase.split(" / ").map(p => p.trim());
      const phaseClass = phases.length > 1 ? "phase-multi" : `phase-${phases[0]}`;

      item.innerHTML = `
        <div class="nav-item-icon ${phaseClass}"></div>
        <div class="nav-item-body">
          <div class="nav-item-name">${s.name}</div>
          <div class="nav-item-desc">${s.shortDesc}</div>
        </div>
      `;
      item.addEventListener("click", () => loadScript(s));
      nav.appendChild(item);
    });
  });
}

/* ═══════════════════════════════════════════════════════ LOAD SCRIPT ════ */

function loadScript(script) {
  currentScript = script;
  originalSrc   = script.source;

  if (editor) {
    editor.setValue(script.source);
    editor.setScrollPosition({ scrollTop: 0 });
    editor.revealLine(1);
  }

  updateMetaBar(script);
  updateInfoPanel(script);
  updateStatusBar(false);
  renderSidebar(activeFilter, document.getElementById("search-input").value);
}

function updateMetaBar(script) {
  document.getElementById("meta-title").textContent = `${script.category.toLowerCase().replace(/ /g, "-")}/${script.name}`;

  const phases = script.irPhase.split(" / ").map(p => p.trim());
  const phaseTags = phases.map(p => `<span class="tag tag-phase-${p}">${p}</span>`).join("");
  const permTag = `<span class="tag tag-perm-${script.permission.includes("Admin") ? "Admin" : "AR"}">${script.permission}</span>`;

  document.getElementById("meta-tags").innerHTML = phaseTags + permTag;
}

function updateInfoPanel(script) {
  document.getElementById("info-description").textContent = script.description;
  document.getElementById("info-usage").textContent = script.usage;

  // Reset checklist when switching scripts
  document.querySelectorAll(".checklist input[type='checkbox']").forEach(cb => { cb.checked = false; });
}

/* ═══════════════════════════════════════════════════════ STATUS BAR ═════ */

function updateStatusBar(isDirty) {
  const chip = document.getElementById("status-modified");
  chip.textContent = isDirty ? "Modified" : "Unmodified";
  chip.className = "status-chip " + (isDirty ? "status-dirty" : "status-clean");
}

function setStatusMsg(msg, durationMs = 2500) {
  const el = document.getElementById("status-msg");
  el.textContent = msg;
  clearTimeout(el._timeout);
  el._timeout = setTimeout(() => { el.textContent = ""; }, durationMs);
}

/* ═══════════════════════════════════════════════════════ MONACO ═════════ */

function initMonaco() {
  require.config({
    paths: { vs: "https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs" }
  });

  require(["vs/editor/editor.main"], () => {
    // Custom dark theme to match our UI
    monaco.editor.defineTheme("rtr-dark", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "comment",           foreground: "6a7390", fontStyle: "italic" },
        { token: "keyword",           foreground: "c792ea" },
        { token: "string",            foreground: "c3e88d" },
        { token: "number",            foreground: "f78c6c" },
        { token: "variable",          foreground: "82aaff" },
        { token: "type",              foreground: "ffcb6b" },
        { token: "delimiter.bracket", foreground: "89ddff" },
      ],
      colors: {
        "editor.background":           "#15171a",
        "editor.foreground":           "#e8eaf0",
        "editor.lineHighlightBackground": "#1c1f24",
        "editorLineNumber.foreground": "#3a3d47",
        "editorLineNumber.activeForeground": "#6a7390",
        "editor.selectionBackground":  "#1e3a5f",
        "editorCursor.foreground":     "#e8002d",
        "editor.findMatchBackground":  "#e8002d44",
        "editorGutter.background":     "#15171a",
        "scrollbarSlider.background":  "#2a2d3566",
        "scrollbarSlider.hoverBackground": "#3a3d4799",
      }
    });

    editor = monaco.editor.create(document.getElementById("editor-container"), {
      value: "",
      language: "powershell",
      theme: "rtr-dark",
      fontFamily: '"Cascadia Code", "Fira Code", "JetBrains Mono", "Consolas", monospace',
      fontSize: 13,
      lineHeight: 22,
      tabSize: 4,
      insertSpaces: true,
      wordWrap: "off",
      minimap: { enabled: true, scale: 1 },
      scrollBeyondLastLine: false,
      renderWhitespace: "selection",
      smoothScrolling: true,
      cursorBlinking: "phase",
      cursorSmoothCaretAnimation: "on",
      padding: { top: 16, bottom: 16 },
      bracketPairColorization: { enabled: true },
      guides: { bracketPairs: true },
      suggest: { showKeywords: true },
      quickSuggestions: true,
      folding: true,
      lineNumbers: "on",
      glyphMargin: false,
    });

    // Track dirty state
    editor.onDidChangeModelContent(() => {
      if (!currentScript) return;
      const isDirty = editor.getValue() !== originalSrc;
      updateStatusBar(isDirty);

      // Live line count
      const lines = editor.getModel()?.getLineCount() ?? 0;
      document.getElementById("status-lines").textContent = `${lines} lines`;
    });

    // Resize when window changes
    window.addEventListener("resize", () => editor.layout());

    // Show the first script by default
    if (window.RTR_SCRIPTS.length > 0) {
      loadScript(window.RTR_SCRIPTS[0]);
    }

    // Remove empty-state placeholder once editor is ready
    document.getElementById("editor-container").querySelector(".editor-empty")?.remove();
  });
}

/* ═══════════════════════════════════════════════════════ TOAST ══════════ */

function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove("show"), 2200);
}

/* ═══════════════════════════════════════════════════════ HEADER ACTIONS ═ */

document.getElementById("btn-copy").addEventListener("click", () => {
  if (!editor) return;
  const text = editor.getValue();
  navigator.clipboard.writeText(text).then(() => {
    showToast("Script copied to clipboard");
  }).catch(() => {
    // Fallback for non-https contexts
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    showToast("Script copied to clipboard");
  });
});

document.getElementById("btn-download").addEventListener("click", () => {
  if (!editor || !currentScript) return;
  const blob = new Blob([editor.getValue()], { type: "text/plain" });
  const a    = document.createElement("a");
  a.href     = URL.createObjectURL(blob);
  a.download = currentScript.name;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`Downloaded ${currentScript.name}`);
});

document.getElementById("btn-reset").addEventListener("click", () => {
  if (!editor || !currentScript) return;
  editor.setValue(originalSrc);
  updateStatusBar(false);
  setStatusMsg("Reset to original");
  showToast("Script reset to original");
});

/* ═══════════════════════════════════════════════════════ SEARCH & FILTER ═ */

document.getElementById("search-input").addEventListener("input", e => {
  renderSidebar(activeFilter, e.target.value);
});

document.querySelectorAll(".filter-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    activeFilter = btn.dataset.filter;
    renderSidebar(activeFilter, document.getElementById("search-input").value);
  });
});

/* ═══════════════════════════════════════════════════════ KEYBOARD SHORTCUTS */

document.addEventListener("keydown", e => {
  // Ctrl/Cmd + S → copy (most useful action in a read context)
  if ((e.ctrlKey || e.metaKey) && e.key === "s") {
    e.preventDefault();
    document.getElementById("btn-copy").click();
  }
  // Ctrl/Cmd + D → download
  if ((e.ctrlKey || e.metaKey) && e.key === "d") {
    e.preventDefault();
    document.getElementById("btn-download").click();
  }
  // Escape → clear search
  if (e.key === "Escape") {
    const si = document.getElementById("search-input");
    if (document.activeElement === si) {
      si.value = "";
      renderSidebar(activeFilter, "");
    }
  }
});

/* ═══════════════════════════════════════════════════════ BOOT ═══════════ */

// Initial sidebar render
renderSidebar("all", "");

// Boot Monaco
initMonaco();
