/**
 * app.js — RTR Labs
 *
 * Features:
 *  • Monaco editor with PowerShell syntax + custom theme
 *  • Sidebar with live search + IR phase filter
 *  • URL hash routing (bookmarkable/shareable scripts)
 *  • Smooth fade transition on script switch
 *  • Parameter injection UI → generates RTR runscript command
 *  • IR Workflow modal (phase-organised script browser)
 *  • Export all scripts as structured .zip
 *  • New script template generator
 *  • Per-script page title + share link
 */

/* ═══════════════════════════════════ STATE ══════════════════════════════ */
let editor          = null;
let currentScript   = null;
let originalSrc     = "";
let activeFilter    = "all";
let activePlatform  = "crowdstrike";
let paramValues     = {};   // current values for the param form

const CATEGORIES = [
  "Triage", "Process Investigation", "Artefact Collection",
  "Persistence", "Lateral Movement", "Credential Indicators",
  "File System IOCs", "Remediation",
];

/* ═══════════════════════════════════ PLATFORM DEFINITIONS ══════════════ */

const PLATFORMS = {
  crowdstrike: {
    id:         "crowdstrike",
    label:      "CrowdStrike",
    color:      "#e8002d",
    generateCmd(script, paramStr) {
      const folder = script.category.toLowerCase().replace(/ /g, "-");
      const base   = `runscript -CloudFile="${folder}/${script.name}"`;
      return paramStr ? `${base} \\\n  -CommandLine="${paramStr}"` : base;
    },
    quickref: [
      { label: "Run script",  cmd: `runscript -CloudFile="category/name.ps1"` },
      { label: "Get file",    cmd: `get C:\\path\\to\\file` },
      { label: "Put file",    cmd: `put C:\\destination` },
      { label: "List files",  cmd: `ls C:\\Windows\\Temp` },
    ],
  },
  sentinelone: {
    id:         "sentinelone",
    label:      "SentinelOne",
    color:      "#7c3aed",
    generateCmd(script) {
      return `// SentinelOne Singularity:\n// Sentinels → select host → Actions\n// → Run Script → upload ${script.name}`;
    },
    quickref: [
      { label: "Run script",   cmd: `Sentinels → host → Actions → Run Script` },
      { label: "Fetch file",   cmd: `Actions → Fetch Files → enter path` },
      { label: "Remote Shell", cmd: `Actions → Remote Shell → connect` },
      { label: "Kill process", cmd: `Actions → Kill Process → enter PID` },
    ],
  },
  defender: {
    id:         "defender",
    label:      "Defender",
    color:      "#0078d4",
    generateCmd(script) {
      return `// MDE Live Response:\nputfile ${script.name}\nrun ${script.name}`;
    },
    quickref: [
      { label: "Run script",    cmd: `putfile script.ps1\nrun script.ps1` },
      { label: "Get file",      cmd: `getfile C:\\path\\to\\file` },
      { label: "List directory",cmd: `dir C:\\Windows\\Temp` },
      { label: "List processes",cmd: `processes` },
    ],
  },
};

function setPlatform(id) {
  activePlatform = id;

  // Update header buttons
  document.querySelectorAll(".platform-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.platform === id);
  });

  // Update status bar indicator
  const p = PLATFORMS[id];
  const dot = document.getElementById("platform-dot");
  const lbl = document.getElementById("platform-label");
  if (dot) dot.style.background = p.color;
  if (lbl) lbl.textContent = p.label;

  // Refresh UI
  updateQuickRef();
  if (currentScript) updateInfoPanel(currentScript);
  renderSidebar(activeFilter, document.getElementById("search-input").value);
}

function updateQuickRef() {
  const qr  = document.getElementById("quick-ref");
  if (!qr) return;
  const ref = PLATFORMS[activePlatform].quickref;
  qr.innerHTML = ref.map(item =>
    `<div class="qr-item"><span class="qr-label">${item.label}</span><code>${escapeHtml(item.cmd)}</code></div>`
  ).join("");
}

function escapeHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

document.querySelectorAll(".platform-btn").forEach(btn => {
  btn.addEventListener("click", () => setPlatform(btn.dataset.platform));
});

/* ═══════════════════════════════════ SIDEBAR ════════════════════════════ */

function renderSidebar(filter = "all", query = "") {
  const nav = document.getElementById("script-nav");
  const q   = query.toLowerCase().trim();
  nav.innerHTML = "";
  let total = 0;

  CATEGORIES.forEach(cat => {
    const scripts = window.RTR_SCRIPTS.filter(s => {
      const matchesCat   = s.category === cat;
      const matchesPhase = filter === "all" || s.irPhase.includes(filter);
      const matchesQuery = !q ||
        s.name.toLowerCase().includes(q) ||
        s.shortDesc.toLowerCase().includes(q) ||
        s.category.toLowerCase().includes(q);
      return matchesCat && matchesPhase && matchesQuery;
    });

    if (scripts.length === 0) return;
    total += scripts.length;

    const label = document.createElement("div");
    label.className = "nav-group-label";
    label.textContent = cat;
    nav.appendChild(label);

    scripts.forEach(s => {
      const supported = !s.supportedPlatforms || s.supportedPlatforms.includes(activePlatform);
      const item = document.createElement("div");
      item.className = "nav-item" +
        (currentScript?.id === s.id ? " active" : "") +
        (supported ? "" : " platform-unavailable");
      item.dataset.id = s.id;
      const phases = s.irPhase.split(" / ").map(p => p.trim());
      const phaseClass = phases.length > 1 ? "phase-multi" : `phase-${phases[0]}`;
      const badge = !supported
        ? `<span class="nav-item-platform-badge">CS only</span>`
        : "";
      item.innerHTML = `
        <div class="nav-item-icon ${phaseClass}"></div>
        <div class="nav-item-body">
          <div class="nav-item-name">${s.name}</div>
          <div class="nav-item-desc">${s.shortDesc}</div>
          ${badge}
        </div>`;
      if (supported) {
        item.addEventListener("click", () => loadScriptWithTransition(s));
      }
      nav.appendChild(item);
    });
  });

  if (total === 0) {
    nav.innerHTML = `<div class="nav-empty">No scripts match "${query}"</div>`;
  }

  const countEl = document.getElementById("script-count");
  if (countEl) {
    countEl.textContent = total === window.RTR_SCRIPTS.length
      ? `${total} scripts`
      : `${total} of ${window.RTR_SCRIPTS.length} scripts`;
  }
}

/* ═══════════════════════════════════ LOAD SCRIPT ════════════════════════ */

function loadScriptWithTransition(script) {
  const container = document.getElementById("editor-container");
  container.classList.add("fading");
  setTimeout(() => {
    loadScript(script);
    container.classList.remove("fading");
  }, 120);
}

function loadScript(script) {
  currentScript = script;
  originalSrc   = script.source;
  paramValues   = buildDefaultParams(script);

  if (editor) {
    editor.setValue(script.source);
    editor.setScrollPosition({ scrollTop: 0 });
    editor.revealLine(1);
  }

  // URL hash routing — makes scripts bookmarkable
  history.replaceState(null, "", `#${script.id}`);

  // Page title
  document.title = `${script.name} — RTR Labs`;

  updateMetaBar(script);
  updateInfoPanel(script);
  updateStatusBar(false);
  renderSidebar(activeFilter, document.getElementById("search-input").value);
}

function buildDefaultParams(script) {
  const defaults = {};
  if (!script.params) return defaults;
  script.params.forEach(p => {
    if (p.type === "boolean") defaults[p.name] = p.default ?? false;
    else defaults[p.name] = "";
  });
  return defaults;
}

/* ═══════════════════════════════════ META BAR ═══════════════════════════ */

function updateMetaBar(script) {
  const titleEl = document.getElementById("meta-title");
  titleEl.textContent = `${script.category.toLowerCase().replace(/ /g, "-")}/${script.name}`;
  titleEl.classList.add("has-script");

  const phases   = script.irPhase.split(" / ").map(p => p.trim());
  const phaseTags = phases.map(p => `<span class="tag tag-phase-${p}">${p}</span>`).join("");
  const permTag   = `<span class="tag tag-perm-${script.permission.includes("Admin") ? "Admin" : "AR"}">${script.permission}</span>`;
  document.getElementById("meta-tags").innerHTML = phaseTags + permTag;
}

/* ═══════════════════════════════════ INFO PANEL ═════════════════════════ */

function updateInfoPanel(script) {
  document.getElementById("info-description").textContent = script.description;

  // Platform-specific usage text
  let usageText;
  if (activePlatform === "crowdstrike") {
    usageText = script.usage;
  } else {
    usageText = PLATFORMS[activePlatform].generateCmd(script, null);
  }
  document.getElementById("info-usage").textContent = usageText;

  document.querySelectorAll(".checklist input[type='checkbox']").forEach(cb => { cb.checked = false; });

  const paramSection = document.getElementById("param-section");
  if (script.params && script.params.length > 0) {
    paramSection.style.display = "";
    renderParamForm(script);
  } else {
    paramSection.style.display = "none";
  }
}



/* ═══════════════════════════════════ PARAM FORM ═════════════════════════ */

function renderParamForm(script) {
  const form = document.getElementById("param-form");
  form.innerHTML = "";

  script.params.forEach(p => {
    const field = document.createElement("div");
    field.className = "param-field";

    const label = document.createElement("label");
    label.className = "param-label";
    label.innerHTML = `<span>-${p.name}</span><span class="param-type-badge">${p.type}</span>`;

    let input;

    if (p.type === "boolean") {
      input = document.createElement("div");
      input.className = "param-toggle";
      const trueBtn  = document.createElement("button");
      const falseBtn = document.createElement("button");
      trueBtn.type  = "button";
      falseBtn.type = "button";
      trueBtn.className  = "param-toggle-btn" + (paramValues[p.name] === true  ? " selected-true"  : "");
      falseBtn.className = "param-toggle-btn" + (paramValues[p.name] === false ? " selected-false" : "");
      trueBtn.textContent  = "$true";
      falseBtn.textContent = "$false";
      trueBtn.addEventListener("click", () => {
        paramValues[p.name] = true;
        trueBtn.className  = "param-toggle-btn selected-true";
        falseBtn.className = "param-toggle-btn";
        updateGeneratedCommand(script);
      });
      falseBtn.addEventListener("click", () => {
        paramValues[p.name] = false;
        trueBtn.className  = "param-toggle-btn";
        falseBtn.className = "param-toggle-btn selected-false";
        updateGeneratedCommand(script);
      });
      input.appendChild(trueBtn);
      input.appendChild(falseBtn);
    } else {
      input = document.createElement("input");
      input.className   = "param-input";
      input.type        = "text";
      input.placeholder = p.placeholder || "";
      input.value       = paramValues[p.name] || "";
      input.addEventListener("input", e => {
        paramValues[p.name] = e.target.value;
        updateGeneratedCommand(script);
      });
    }

    const hint = document.createElement("div");
    hint.className   = "param-hint";
    hint.textContent = p.hint || "";

    field.appendChild(label);
    field.appendChild(input);
    if (p.hint) field.appendChild(hint);
    form.appendChild(field);
  });

  updateGeneratedCommand(script);
}

function updateGeneratedCommand(script) {
  const parts = [];

  script.params.forEach(p => {
    const val = paramValues[p.name];
    if (val === "" || val === null || val === undefined) return;

    if (p.type === "boolean") {
      parts.push(`-${p.name} $${val}`);
    } else if (p.type === "number") {
      if (val !== "") parts.push(`-${p.name} ${val}`);
    } else {
      const safe = String(val).replace(/'/g, "''");
      if (safe !== "") parts.push(`-${p.name} '${safe}'`);
    }
  });

  const paramStr = parts.join(" ");
  const cmd = PLATFORMS[activePlatform].generateCmd(script, paramStr || null);
  document.getElementById("param-cmd").textContent = cmd;
}

document.getElementById("btn-copy-cmd").addEventListener("click", () => {
  const cmd = document.getElementById("param-cmd").textContent;
  copyToClipboard(cmd);
  showToast("Command copied to clipboard");
});

/* ═══════════════════════════════════ STATUS BAR ═════════════════════════ */

function updateStatusBar(isDirty) {
  const chip = document.getElementById("status-modified");
  chip.textContent = isDirty ? "Modified" : "Unmodified";
  chip.className   = "status-chip " + (isDirty ? "status-dirty" : "status-clean");
}

function setStatusMsg(msg, ms = 2500) {
  const el = document.getElementById("status-msg");
  el.textContent = msg;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.textContent = ""; }, ms);
}

/* ═══════════════════════════════════ WORKFLOW MODAL ═════════════════════ */

const WORKFLOW_PHASES = [
  {
    key: "Identification",
    label: "Identification",
    cssClass: "phase-id",
  },
  {
    key: "Containment",
    label: "Containment",
    cssClass: "phase-contain",
  },
  {
    key: "Eradication",
    label: "Eradication",
    cssClass: "phase-erad",
  },
];

function openWorkflowModal() {
  const cols = document.getElementById("workflow-columns");
  cols.innerHTML = "";

  WORKFLOW_PHASES.forEach(phase => {
    const col = document.createElement("div");
    col.className = "workflow-phase";

    const header = document.createElement("div");
    header.className = `workflow-phase-header ${phase.cssClass}`;
    header.innerHTML = `
      <div class="workflow-phase-dot"></div>
      <span class="workflow-phase-name">${phase.label}</span>`;
    col.appendChild(header);

    const scripts = window.RTR_SCRIPTS.filter(s => s.irPhase.includes(phase.key));
    scripts.forEach(s => {
      const card = document.createElement("div");
      card.className = "workflow-script-card" + (currentScript?.id === s.id ? " active" : "");
      card.innerHTML = `
        <div class="workflow-card-name">${s.name}</div>
        <div class="workflow-card-desc">${s.shortDesc}</div>
        <span class="workflow-card-perm">${s.permission}</span>`;
      card.addEventListener("click", () => {
        closeWorkflowModal();
        loadScriptWithTransition(s);
      });
      col.appendChild(card);
    });

    cols.appendChild(col);
  });

  document.getElementById("workflow-modal").classList.add("open");
  document.getElementById("workflow-modal").setAttribute("aria-hidden", "false");
}

function closeWorkflowModal() {
  document.getElementById("workflow-modal").classList.remove("open");
  document.getElementById("workflow-modal").setAttribute("aria-hidden", "true");
}

document.getElementById("btn-workflow").addEventListener("click", openWorkflowModal);
document.getElementById("workflow-close").addEventListener("click", closeWorkflowModal);
document.getElementById("workflow-modal").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeWorkflowModal();
});

/* ═══════════════════════════════════ NEW SCRIPT TEMPLATE ════════════════ */

const NEW_SCRIPT_TEMPLATE = `<#
.SYNOPSIS
    Script Name - One-line description.

.DESCRIPTION
    Detailed description of what this script does and why.
    Include key indicators it looks for and what output to expect.

.IR_PHASE
    Identification
    # Options: Identification | Containment | Eradication

.RTR_PERMISSION
    Active Responder
    # Options: Active Responder | RTR Admin

.NOTES
    Safe to run : Yes
    Disk writes : None
    Execution   : ~X seconds

.EXAMPLE
    runscript -CloudFile="category/script-name.ps1"
#>

# ── Section Heading ───────────────────────────────────────────────────────────
# Explain WHY this check matters, not just what it does
Write-Output "===== SCRIPT NAME ====="

# Your code here

Write-Output "===== END SCRIPT NAME ====="
`;

document.getElementById("btn-new").addEventListener("click", () => {
  // Unset current script selection
  currentScript = null;
  originalSrc   = NEW_SCRIPT_TEMPLATE;

  const titleEl = document.getElementById("meta-title");
  titleEl.textContent = "new-script.ps1";
  titleEl.classList.add("has-script");
  document.getElementById("meta-tags").innerHTML = "";
  document.getElementById("info-description").textContent = "Edit the template below, then download your script.";
  document.getElementById("info-usage").textContent = 'runscript -CloudFile="category/new-script.ps1"';
  document.getElementById("param-section").style.display = "none";
  document.querySelectorAll(".checklist input[type='checkbox']").forEach(cb => { cb.checked = false; });
  document.title = "New Script — RTR Labs";
  history.replaceState(null, "", "#new");

  if (editor) {
    const container = document.getElementById("editor-container");
    container.classList.add("fading");
    setTimeout(() => {
      editor.setValue(NEW_SCRIPT_TEMPLATE);
      editor.setScrollPosition({ scrollTop: 0 });
      editor.revealLine(1);
      container.classList.remove("fading");
    }, 120);
  }

  renderSidebar(activeFilter, document.getElementById("search-input").value);
  showToast("New script template loaded — edit and download when ready");
});

/* ═══════════════════════════════════ EXPORT ZIP ═════════════════════════ */

document.getElementById("btn-export-all").addEventListener("click", async () => {
  if (typeof JSZip === "undefined") {
    showToast("JSZip not loaded — check your connection");
    return;
  }

  const zip = new JSZip();

  // Folder structure mirrors the repo
  const folderMap = {
    "Triage":                 "triage",
    "Process Investigation":  "process-investigation",
    "Artefact Collection":    "artefact-collection",
    "Persistence":            "persistence",
    "Lateral Movement":       "lateral-movement",
    "Credential Indicators":  "credential-indicators",
    "File System IOCs":       "file-system-iocs",
    "Remediation":            "remediation",
  };

  window.RTR_SCRIPTS.forEach(s => {
    const folder = folderMap[s.category] || s.category.toLowerCase().replace(/ /g, "-");
    zip.folder(folder).file(s.name, s.source);
  });

  // Add a minimal README stub
  zip.file("README.md", `# RTR Script Collection\nDownloaded from rtrlabs.io\n\nSee https://rtrlabs.io for full documentation.\n`);

  const blob = await zip.generateAsync({ type: "blob" });
  const a    = document.createElement("a");
  a.href     = URL.createObjectURL(blob);
  a.download = "rtr-scripts.zip";
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`Downloaded ${window.RTR_SCRIPTS.length} scripts as rtr-scripts.zip`);
});

/* ═══════════════════════════════════ HEADER ACTIONS ════════════════════ */

document.getElementById("btn-copy").addEventListener("click", () => {
  if (!editor) return;
  copyToClipboard(editor.getValue());
  showToast("Script copied to clipboard");
});

document.getElementById("btn-download").addEventListener("click", () => {
  if (!editor) return;
  const name = currentScript?.name ?? "new-script.ps1";
  const blob = new Blob([editor.getValue()], { type: "text/plain" });
  const a    = document.createElement("a");
  a.href     = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
  showToast(`Downloaded ${name}`);
});

document.getElementById("btn-reset").addEventListener("click", () => {
  if (!editor) return;
  const container = document.getElementById("editor-container");
  container.classList.add("fading");
  setTimeout(() => {
    editor.setValue(originalSrc);
    container.classList.remove("fading");
    updateStatusBar(false);
    showToast("Reset to original");
  }, 120);
});

document.getElementById("btn-share").addEventListener("click", () => {
  if (!currentScript) return;
  const url = `${location.origin}${location.pathname}#${currentScript.id}`;
  copyToClipboard(url);
  showToast("Share link copied to clipboard");
});

/* ═══════════════════════════════════ SEARCH & FILTER ═══════════════════ */

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

/* ═══════════════════════════════════ KEYBOARD ═══════════════════════════ */

document.addEventListener("keydown", e => {
  const searchInput = document.getElementById("search-input");

  // / → focus search
  if (e.key === "/" && document.activeElement !== searchInput && !e.ctrlKey && !e.metaKey) {
    e.preventDefault();
    searchInput.focus();
    searchInput.select();
  }
  // Escape → blur search / close modal
  if (e.key === "Escape") {
    if (document.getElementById("workflow-modal").classList.contains("open")) {
      closeWorkflowModal();
    } else if (document.activeElement === searchInput) {
      searchInput.blur();
      searchInput.value = "";
      renderSidebar(activeFilter, "");
    }
  }
  // Ctrl/Cmd+S → copy
  if ((e.ctrlKey || e.metaKey) && e.key === "s") {
    e.preventDefault();
    document.getElementById("btn-copy").click();
  }
  // Ctrl/Cmd+D → download
  if ((e.ctrlKey || e.metaKey) && e.key === "d") {
    e.preventDefault();
    document.getElementById("btn-download").click();
  }
});

/* ═══════════════════════════════════ HASH ROUTING ═══════════════════════ */

function loadFromHash() {
  const id = location.hash.replace("#", "");
  if (!id || id === "new") return;
  const script = window.RTR_SCRIPTS.find(s => s.id === id);
  if (script) loadScript(script);
}

window.addEventListener("hashchange", loadFromHash);

/* ═══════════════════════════════════ UTILITIES ══════════════════════════ */

function copyToClipboard(text) {
  if (navigator.clipboard) {
    navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  Object.assign(ta.style, { position: "fixed", opacity: "0" });
  document.body.appendChild(ta);
  ta.select();
  document.execCommand("copy");
  document.body.removeChild(ta);
}

function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove("show"), 2400);
}

/* ═══════════════════════════════════ MONACO ═════════════════════════════ */

function initMonaco() {
  require.config({
    paths: { vs: "https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs" }
  });

  require(["vs/editor/editor.main"], () => {
    monaco.editor.defineTheme("rtr-dark", {
      base: "vs-dark",
      inherit: true,
      rules: [
        { token: "comment",           foreground: "5a6380", fontStyle: "italic" },
        { token: "keyword",           foreground: "c792ea" },
        { token: "string",            foreground: "c3e88d" },
        { token: "number",            foreground: "f78c6c" },
        { token: "variable",          foreground: "82aaff" },
        { token: "type",              foreground: "ffcb6b" },
        { token: "delimiter.bracket", foreground: "89ddff" },
        { token: "operator",          foreground: "89ddff" },
      ],
      colors: {
        "editor.background":              "#15171a",
        "editor.foreground":              "#e8eaf0",
        "editor.lineHighlightBackground": "#1c1f2400",
        "editor.lineHighlightBorder":     "#22262d",
        "editorLineNumber.foreground":    "#2e3240",
        "editorLineNumber.activeForeground": "#5a6380",
        "editor.selectionBackground":     "#1a2e4a",
        "editorCursor.foreground":        "#e8002d",
        "editorCursor.background":        "#15171a",
        "editor.findMatchBackground":     "#e8002d40",
        "editor.findMatchHighlightBackground": "#e8002d20",
        "editorGutter.background":        "#15171a",
        "scrollbarSlider.background":     "#2a2d3555",
        "scrollbarSlider.hoverBackground":"#3a3d4788",
        "editorIndentGuide.background1":  "#222530",
        "editorBracketMatch.background":  "#1a2e4a",
        "editorBracketMatch.border":      "#3b82f660",
        "minimap.background":             "#13151850",
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
      minimap: { enabled: true, scale: 1, renderCharacters: false },
      scrollBeyondLastLine: false,
      renderWhitespace: "selection",
      smoothScrolling: true,
      cursorBlinking: "phase",
      cursorSmoothCaretAnimation: "on",
      padding: { top: 14, bottom: 14 },
      bracketPairColorization: { enabled: true },
      guides: { bracketPairs: "active" },
      folding: true,
      lineNumbers: "on",
      glyphMargin: false,
      renderLineHighlight: "line",
      overviewRulerBorder: false,
      hideCursorInOverviewRuler: true,
      occurrencesHighlight: "off",
      quickSuggestions: { other: true, comments: false, strings: false },
    });

    editor.onDidChangeModelContent(() => {
      if (!currentScript && editor.getValue() === NEW_SCRIPT_TEMPLATE) return;
      const isDirty = editor.getValue() !== originalSrc;
      updateStatusBar(isDirty);
      const lines = editor.getModel()?.getLineCount() ?? 0;
      document.getElementById("status-lines").textContent = `${lines} lines`;
    });

    window.addEventListener("resize", () => editor.layout());

    // Load from URL hash, or fall back to first script
    if (location.hash && location.hash !== "#new") {
      loadFromHash();
    } else if (window.RTR_SCRIPTS.length > 0) {
      loadScript(window.RTR_SCRIPTS[0]);
    }
  });
}

/* ═══════════════════════════════════ BOOT ═══════════════════════════════ */

renderSidebar("all", "");
setPlatform("crowdstrike");   // initialise platform indicator + quick ref
initMonaco();
