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
let activeOS        = "windows";
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
      if (activeOS === "macos") {
        return `// MDE on macOS:\n// MDE for Mac uses osquery/sensor — Live Response\n// may not be available. Use CrowdStrike or S1 for\n// full remote scripting on macOS endpoints.`;
      }
      return `// MDE Live Response:\n// 1. Upload to library first:\n//    Settings → Endpoints → Live Response\n//    → Upload files to library\n// 2. In Live Response session:\nputfile ${script.name}\nrun ${script.name}`;
    },
    quickref: [
      { label: "Upload to library", cmd: `Settings → Endpoints → Live Response → Upload files to library` },
      { label: "Run script",        cmd: `putfile script.ps1\nrun script.ps1` },
      { label: "Get file",          cmd: `getfile C:\\path\\to\\file` },
      { label: "List directory",    cmd: `dir C:\\Windows\\Temp` },
      { label: "List processes",    cmd: `processes` },
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

/* ═══════════════════════════════════ OS DEFINITIONS ════════════════════ */

const OS_DEFS = {
  windows: { label: "Windows", monacoLang: "powershell", langLabel: "PowerShell · UTF-8" },
  macos:   { label: "macOS",   monacoLang: "shell",      langLabel: "Bash · UTF-8" },
  linux:   { label: "Linux",   monacoLang: "shell",      langLabel: "Bash · UTF-8" },
};

function setOS(id) {
  activeOS = id;

  // Sidebar OS buttons
  document.querySelectorAll(".os-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.os === id));

  // Header badge
  const badge = document.getElementById("brand-os-label");
  if (badge) badge.textContent = OS_DEFS[id].label;

  // Status bar language label
  const langEl = document.getElementById("status-lang");
  if (langEl) langEl.textContent = OS_DEFS[id].langLabel;

  // Monaco language
  if (editor && currentScript) {
    const model = editor.getModel();
    if (model) monaco.editor.setModelLanguage(model, OS_DEFS[id].monacoLang);
  }

  // On macOS/Linux, MDE platform is less applicable — keep but don't auto-switch
  // Save preference
  localStorage.setItem("rtr_os", id);

  // Reload sidebar + deselect if current script doesn't match OS
  if (currentScript && currentScript.os !== id) {
    currentScript = null;
    const titleEl = document.getElementById("meta-title");
    if (titleEl) { titleEl.textContent = "Select a script"; titleEl.classList.remove("has-script"); }
    document.getElementById("meta-tags").innerHTML = "";
    document.getElementById("info-description").textContent = "—";
    document.getElementById("info-usage").textContent = "—";
    document.getElementById("param-section").style.display = "none";
    if (editor) editor.setValue("");
    history.replaceState(null, "", location.pathname);
  }

  renderSidebar(activeFilter, document.getElementById("search-input").value);
}

document.querySelectorAll(".os-btn").forEach(btn => {
  btn.addEventListener("click", () => setOS(btn.dataset.os));
});

/* ═══════════════════════════════════ LANDING PAGE ══════════════════════ */

(function initLanding() {
  const overlay     = document.getElementById("landing");
  const step2       = document.getElementById("landing-step2");
  const enterBtn    = document.getElementById("landing-enter");
  const skipBtn     = document.getElementById("landing-skip");
  const brandBadge  = document.getElementById("brand-os-badge");

  let landingOS       = null;
  let landingPlatform = null;

  // If user has visited before, skip landing
  const savedOS       = localStorage.getItem("rtr_os");
  const savedPlatform = localStorage.getItem("rtr_platform");
  if (savedOS && savedPlatform) {
    overlay.classList.add("hidden");
    setOS(savedOS);
    setPlatform(savedPlatform);
    return;
  }

  // OS tile click
  document.querySelectorAll(".os-tile").forEach(tile => {
    tile.addEventListener("click", () => {
      document.querySelectorAll(".os-tile").forEach(t => t.classList.remove("selected"));
      tile.classList.add("selected");
      landingOS = tile.dataset.os;
      step2.classList.add("visible");
      checkEnterReady();
    });
  });

  // Platform button click (landing)
  document.querySelectorAll(".landing-plat-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".landing-plat-btn").forEach(b => b.classList.remove("selected"));
      btn.classList.add("selected");
      landingPlatform = btn.dataset.platform;
      checkEnterReady();
    });
  });

  function checkEnterReady() {
    enterBtn.disabled = !(landingOS && landingPlatform);
  }

  function dismissLanding() {
    if (landingOS)       setOS(landingOS);
    if (landingPlatform) setPlatform(landingPlatform);
    localStorage.setItem("rtr_os",       landingOS       || "windows");
    localStorage.setItem("rtr_platform", landingPlatform || "crowdstrike");
    overlay.classList.add("dismissing");
    setTimeout(() => overlay.classList.add("hidden"), 420);
  }

  enterBtn.addEventListener("click", () => { if (!enterBtn.disabled) dismissLanding(); });
  skipBtn.addEventListener("click",  dismissLanding);

  // Brand badge re-opens landing
  brandBadge.addEventListener("click", () => {
    overlay.classList.remove("hidden", "dismissing");
    // Pre-select current choices
    document.querySelectorAll(".os-tile").forEach(t => {
      t.classList.toggle("selected", t.dataset.os === activeOS);
    });
    document.querySelectorAll(".landing-plat-btn").forEach(b => {
      b.classList.toggle("selected", b.dataset.platform === activePlatform);
    });
    landingOS       = activeOS;
    landingPlatform = activePlatform;
    step2.classList.add("visible");
    checkEnterReady();
  });
})();

/* ═══════════════════════════════════ SIDEBAR ════════════════════════════ */

function renderSidebar(filter = "all", query = "") {
  const nav = document.getElementById("script-nav");
  const q   = query.toLowerCase().trim();
  nav.innerHTML = "";
  let total = 0;

  CATEGORIES.forEach(cat => {
    const scripts = window.RTR_SCRIPTS.filter(s => {
      const matchesCat   = s.category === cat;
      const matchesOS    = s.os === activeOS;
      const matchesPhase = filter === "all" || s.irPhase.includes(filter);
      const matchesQuery = !q ||
        s.name.toLowerCase().includes(q) ||
        s.shortDesc.toLowerCase().includes(q) ||
        s.category.toLowerCase().includes(q);
      return matchesCat && matchesOS && matchesPhase && matchesQuery;
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
    const osTotal = window.RTR_SCRIPTS.filter(s => s.os === activeOS).length;
    countEl.textContent = total === osTotal
      ? `${total} scripts`
      : `${total} of ${osTotal} scripts`;
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
    // Switch Monaco language to match script OS
    const lang = OS_DEFS[script.os]?.monacoLang || "powershell";
    const model = editor.getModel();
    if (model) monaco.editor.setModelLanguage(model, lang);
    // Update status bar language label
    const langEl = document.getElementById("status-lang");
    if (langEl) langEl.textContent = OS_DEFS[script.os]?.langLabel || "PowerShell · UTF-8";
  }

  // URL hash + localStorage — bookmarkable and reload-persistent
  history.replaceState(null, "", `#${script.id}`);
  localStorage.setItem("rtr_last_script", script.id);

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

  renderChecklist(script);

  const paramSection = document.getElementById("param-section");
  if (script.params && script.params.length > 0) {
    paramSection.style.display = "";
    renderParamForm(script);
  } else {
    paramSection.style.display = "none";
  }
}



/* ═══════════════════════════════════ CHECKLIST ══════════════════════════ */

function buildChecklistItems(script) {
  const items = [];
  items.push({ text: "Reviewed script logic and understood the output format", key: "review" });
  items.push({ text: "Confirmed correct host / asset ID targeted",             key: "host" });

  if (script) {
    if (script.irPhase?.includes("Eradication")) {
      items.push({ text: "Verified exact target — triple-check name, PID, path or value name", key: "target", warn: true });
      items.push({ text: "Forensic evidence / artefact captured before removal",               key: "forensic", warn: true });
    }
    if (script.irPhase?.includes("Containment")) {
      items.push({ text: "Authorised by IR lead / SOC manager before isolating", key: "auth", warn: true });
    }
    if (script.params?.length > 0) {
      items.push({ text: "Parameters confirmed with incident owner", key: "params" });
    }
    if (script.permission?.includes("Admin")) {
      items.push({ text: "Elevated RTR Admin session confirmed (not Active Responder)", key: "admin" });
    }
  }

  items.push({ text: "Output documented in case management system", key: "docs" });
  return items;
}

function renderChecklist(script) {
  const ul      = document.getElementById("info-checklist");
  const items   = buildChecklistItems(script);
  const saveKey = script ? `rtr_cl_${script.id}` : null;
  const saved   = saveKey ? JSON.parse(localStorage.getItem(saveKey) || "{}") : {};

  ul.innerHTML = items.map((item, i) => `
    <li class="${item.warn ? "checklist-warn" : ""}">
      <label>
        <input type="checkbox" data-idx="${i}" ${saved[i] ? "checked" : ""} />
        <span>${item.text}</span>
      </label>
    </li>`).join("");

  if (saveKey) {
    ul.querySelectorAll("input[type='checkbox']").forEach((cb, i) => {
      cb.addEventListener("change", () => {
        const state = {};
        ul.querySelectorAll("input[type='checkbox']").forEach((c, j) => { state[j] = c.checked; });
        localStorage.setItem(saveKey, JSON.stringify(state));
      });
    });
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

    const scripts = window.RTR_SCRIPTS.filter(s => s.irPhase.includes(phase.key) && s.os === activeOS);
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
  renderChecklist(null);
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
    const subdir   = folderMap[s.category] || s.category.toLowerCase().replace(/ /g, "-");
    const osPrefix = s.os !== "windows" ? `${s.os}/` : "";
    zip.folder(osPrefix + subdir).file(s.name, s.source);
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

    // Load from URL hash → or last-used script → or first script for active OS
    if (location.hash && location.hash !== "#new") {
      loadFromHash();
    } else {
      const lastId = localStorage.getItem("rtr_last_script");
      const fallback = (lastId && window.RTR_SCRIPTS.find(s => s.id === lastId && s.os === activeOS))
        || window.RTR_SCRIPTS.find(s => s.os === activeOS);
      if (fallback) loadScript(fallback);
    }
  });
}

/* ═══════════════════════════════════ BOOT ═══════════════════════════════ */

renderSidebar("all", "");
// Boot: platform + quick ref initialised by landing page or localStorage defaults
// OS buttons default to 'windows' (set in HTML), platform dot set by setPlatform
setPlatform(localStorage.getItem("rtr_platform") || "crowdstrike");
initMonaco();
