(function () {
  "use strict";

  const Scanner = window.ShareSafe;
  const $ = (id) => document.getElementById(id);

  const input = $("input");
  const drop = $("drop");
  const fileInput = $("fileInput");
  const findingsEl = $("findings");
  const verdict = $("verdict");
  const output = $("output");
  const copyBtn = $("copyBtn");
  const downloadBtn = $("downloadBtn");
  const status = $("status");
  const inputStats = $("inputStats");
  const fileStatus = $("fileStatus");
  const scanInfo = $("scanInfo");
  const customTermsEl = $("customTerms");
  const allowTermsEl = $("allowTerms");
  const redactLowEl = $("redactLow");

  const MAX_FILE_BYTES = 25 * 1024 * 1024;
  const CATEGORIES = [
    ["secret", "Secrets and credentials"],
    ["personal", "Personal data"],
    ["financial", "Financial"],
    ["network", "Network and infrastructure"],
    ["custom", "Your terms"]
  ];

  // Browser storage holds only the viewer's own term lists and preferences.
  const store = {
    get(key, fallback) {
      try {
        const raw = window.localStorage.getItem("sharesafe." + key);
        return raw === null ? fallback : JSON.parse(raw);
      } catch (error) {
        return fallback;
      }
    },
    set(key, value) {
      try {
        window.localStorage.setItem("sharesafe." + key, JSON.stringify(value));
      } catch (error) {
        // Storage can be blocked; settings then last for this visit only.
      }
    }
  };

  const settings = {
    customTerms: store.get("customTerms", []),
    allowTerms: store.get("allowTerms", []),
    redactLow: store.get("redactLow", false)
  };

  let text = "";
  let result = { findings: [], groups: [] };
  let loadedName = "";
  const choices = new Map(); // group key -> redact? (only when the user changed it)
  let timer = 0;

  function defaultOn(item) {
    return item.confidence !== "low" || settings.redactLow;
  }
  function isOn(item) {
    return choices.has(item.key) ? choices.get(item.key) : defaultOn(item);
  }

  function mask(group) {
    const v = group.value.replace(/\s+/g, " ");
    if (group.category !== "secret") return v.length > 60 ? v.slice(0, 57) + "…" : v;
    if (v.length <= 8) return "•".repeat(Math.max(4, v.length));
    return v.slice(0, 4) + "…" + v.slice(-2) + " (" + v.length + " chars)";
  }

  function plural(n, one, many) {
    return n + " " + (n === 1 ? one : many || one + "s");
  }

  // ---------------------------------------------------------------------------
  // Scanning
  // ---------------------------------------------------------------------------
  function scanNow() {
    clearTimeout(timer);
    text = input.value;
    const started = performance.now();
    result = text.trim()
      ? Scanner.scan(text, { customTerms: settings.customTerms, allowTerms: settings.allowTerms })
      : { findings: [], groups: [] };
    const elapsed = performance.now() - started;
    for (const key of Array.from(choices.keys())) {
      if (!result.groups.some((g) => g.key === key)) choices.delete(key);
    }
    scanInfo.textContent = text.trim() ? "Checked in " + Math.max(1, Math.round(elapsed)) + " ms" : "";
    updateStats();
    render();
  }

  function scheduleScan() {
    clearTimeout(timer);
    timer = setTimeout(scanNow, input.value.length > 200000 ? 450 : 120);
  }

  function updateStats() {
    if (!text) {
      inputStats.textContent = "Empty";
      return;
    }
    const lines = text.split("\n").length;
    inputStats.textContent = plural(text.length, "character") + " · " + plural(lines, "line");
  }

  // ---------------------------------------------------------------------------
  // Rendering
  // ---------------------------------------------------------------------------
  function render() {
    renderVerdict();
    renderFindings();
    renderOutput();
    const has = Boolean(text.trim());
    copyBtn.disabled = !has;
    downloadBtn.disabled = !has;
  }

  function setVerdict(kind, title, detail) {
    verdict.className = "verdict " + kind;
    verdict.replaceChildren();
    const strong = document.createElement("strong");
    strong.textContent = title;
    verdict.append(strong);
    if (detail) {
      const p = document.createElement("p");
      p.textContent = detail;
      verdict.append(p);
    }
  }

  function renderVerdict() {
    const groups = result.groups;
    if (!text.trim()) {
      setVerdict("neutral", "Nothing to check yet", "Paste text on the left. Secrets, personal data and network details are found as you type.");
      return;
    }
    if (!groups.length) {
      setVerdict("ok", "Nothing found", "No secrets or personal data matched. Patterns can miss things, so give the text a quick read before you share it.");
      return;
    }
    const on = groups.filter(isOn);
    const keptRisky = groups.filter((g) => !isOn(g) && g.confidence !== "low");
    const keptLow = groups.filter((g) => !isOn(g) && g.confidence === "low");
    const byCat = CATEGORIES.map(([cat, name]) => [name, on.filter((g) => g.category === cat).length])
      .filter(([, n]) => n > 0)
      .map(([name, n]) => n + " " + name.toLowerCase());
    const notes = [];
    if (keptLow.length) notes.push(plural(keptLow.length, "low-confidence match", "low-confidence matches") + " (hashes, IDs) left as-is. Tick them to redact.");
    if (keptRisky.length) {
      setVerdict("bad", plural(keptRisky.length, "item") + " you unticked will be shared as-is",
        "Check that each one is safe to share. " + notes.join(" "));
      return;
    }
    if (!on.length) {
      setVerdict("warn", "Only low-confidence matches found", notes.join(" "));
      return;
    }
    setVerdict("ok", plural(on.length, "value") + " will be redacted",
      (byCat.length ? byCat.join(", ") + ". " : "") + "Copy the redacted text below. " + notes.join(" "));
  }

  function renderFindings() {
    findingsEl.replaceChildren();
    if (!result.groups.length) return;
    for (const [cat, name] of CATEGORIES) {
      const items = result.groups.filter((g) => g.category === cat);
      if (!items.length) continue;
      const section = document.createElement("div");
      section.className = "group";

      const head = document.createElement("div");
      head.className = "group-head";
      const all = document.createElement("input");
      all.type = "checkbox";
      all.setAttribute("aria-label", "Redact all " + name.toLowerCase());
      const onCount = items.filter(isOn).length;
      all.checked = onCount === items.length;
      all.indeterminate = onCount > 0 && onCount < items.length;
      all.addEventListener("change", () => {
        for (const g of items) choices.set(g.key, all.checked);
        render();
      });
      const title = document.createElement("span");
      title.textContent = name;
      const count = document.createElement("span");
      count.className = "count";
      count.textContent = "· " + items.length;
      head.append(all, title, count);
      section.append(head);

      items.sort((a, b) => rank(b.confidence) - rank(a.confidence) || a.first - b.first);
      for (const g of items) section.append(renderItem(g));
      findingsEl.append(section);
    }
  }

  function rank(c) {
    return c === "high" ? 3 : c === "medium" ? 2 : 1;
  }

  let itemId = 0;
  function renderItem(g) {
    const on = isOn(g);
    const row = document.createElement("div");
    row.className = "item" + (on ? "" : " off");

    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = on;
    box.id = "item-" + (++itemId);
    box.addEventListener("change", () => {
      choices.set(g.key, box.checked);
      render();
    });

    const body = document.createElement("label");
    body.className = "item-body";
    body.htmlFor = box.id;

    const titleRow = document.createElement("span");
    titleRow.className = "item-title";
    titleRow.append(g.label);
    const badge = document.createElement("span");
    badge.className = "badge " + g.confidence;
    badge.textContent = g.confidence;
    titleRow.append(badge);

    const value = document.createElement("span");
    value.className = "item-value";
    const original = document.createElement("code");
    original.textContent = mask(g);
    const ph = document.createElement("code");
    ph.className = "ph";
    ph.textContent = g.placeholder;
    value.append(original, " → ", ph);

    const meta = document.createElement("span");
    meta.className = "item-meta";
    const parts = [];
    if (g.context) parts.push("from " + g.context);
    parts.push(g.count > 1 ? g.count + " times" : "once");
    const lines = g.lines.slice(0, 6).join(", ") + (g.lines.length > 6 ? ", …" : "");
    parts.push((g.lines.length === 1 ? "line " : "lines ") + lines);
    meta.textContent = parts.join(" · ");

    body.append(titleRow, value, meta);

    const jump = document.createElement("button");
    jump.type = "button";
    jump.className = "jump";
    jump.textContent = "Show";
    jump.setAttribute("aria-label", "Show " + g.label + " in the text");
    jump.addEventListener("click", () => showInInput(g));

    row.append(box, body, jump);
    return row;
  }

  function renderOutput() {
    output.replaceChildren();
    if (!text) return;
    const frag = document.createDocumentFragment();
    for (const seg of Scanner.segments(text, result.findings, (f) => isOn(groupOf(f)))) {
      if (!seg.finding) {
        frag.append(seg.text);
        continue;
      }
      const mark = document.createElement("mark");
      mark.className = seg.redacted ? "ph" : "kept";
      mark.title = seg.finding.label + (seg.redacted ? "" : " (kept)");
      mark.textContent = seg.text;
      frag.append(mark);
    }
    output.append(frag);
  }

  const groupCache = new WeakMap();
  function groupOf(finding) {
    let g = groupCache.get(finding);
    if (!g) {
      g = result.groups.find((x) => x.key === finding.key);
      groupCache.set(finding, g);
    }
    return g;
  }

  function redactedText() {
    return Scanner.redact(text, result.findings, (f) => isOn(groupOf(f)));
  }

  function showInInput(g) {
    const f = result.findings.find((x) => x.key === g.key);
    if (!f) return;
    input.focus();
    input.setSelectionRange(f.start, f.end);
    const lineHeight = parseFloat(getComputedStyle(input).lineHeight) || 20;
    input.scrollTop = Math.max(0, (f.line - 4) * lineHeight);
  }

  // ---------------------------------------------------------------------------
  // Copy, download, files
  // ---------------------------------------------------------------------------
  async function copy() {
    const value = redactedText();
    const count = result.groups.filter(isOn).length;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        const temp = document.createElement("textarea");
        temp.value = value;
        temp.setAttribute("readonly", "");
        temp.style.position = "fixed";
        temp.style.opacity = "0";
        document.body.append(temp);
        temp.select();
        document.execCommand("copy");
        temp.remove();
      }
      status.textContent = "Copied, with " + plural(count, "value") + " redacted.";
    } catch (error) {
      status.textContent = "The browser blocked the clipboard. Select the redacted copy and copy it by hand.";
    }
  }

  function download() {
    const blob = new Blob([redactedText()], { type: "text/plain;charset=utf-8" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = loadedName ? loadedName.replace(/(\.[^.]+)?$/, ".redacted$1") : "redacted.txt";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 0);
    status.textContent = "Saved " + link.download + ".";
  }

  async function loadFile(file) {
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      fileStatus.textContent = file.name + " is larger than 25 MB. Split it first.";
      return;
    }
    try {
      const content = await file.text();
      if (content.slice(0, 4096).includes("\u0000")) {
        fileStatus.textContent = file.name + " looks like a binary file. Export it as text first.";
        return;
      }
      loadedName = file.name;
      input.value = content;
      fileStatus.textContent = "Loaded " + file.name;
      choices.clear();
      scanNow();
    } catch (error) {
      fileStatus.textContent = "Could not read " + file.name + ".";
    }
  }

  // ---------------------------------------------------------------------------
  // Sample text. Fake credentials are assembled at runtime so the repository
  // never contains a complete token that secret scanners would flag.
  // ---------------------------------------------------------------------------
  function sampleText() {
    const k = (...parts) => parts.join("");
    return [
      "2026-10-14 09:12:44 INFO  deploy started by ada.morgan@example.com on DESKTOP-7QK2M9P",
      "2026-10-14 09:12:45 DEBUG cwd=C:\\Users\\amorgan\\source\\billing-api",
      "2026-10-14 09:12:45 DEBUG OPENAI_API_KEY=" + k("sk-", "proj-", "T3x9QmW2vLp8RkZ4nYb6HcJd1FsGa7Ue5Ko0Mi"),
      "2026-10-14 09:12:46 DEBUG connecting to postgres://billing:" + k("Wint", "er2026!") + "@db01.corp.local:5432/billing",
      "2026-10-14 09:12:47 WARN  retry from 10.20.4.17, Authorization: Bearer " +
        k("eyJ", "hbGciOiJIUzI1NiJ9", ".", "eyJ", "zdWIiOiJhbW9yZ2FuIn0", ".", "Qm9ndXNTaWduYXR1cmVGb3JEZW1v"),
      "2026-10-14 09:12:48 ERROR upload failed: https://billingstore01.blob.core.windows.net/exports?sv=2022-11-02&sig=" +
        k("q8Yt2LmN4vXc", "7RbZ0aKe3WfP9sJu1HdG5oT6iE%3D"),
      "2026-10-14 09:12:49 DEBUG fallback key " + k("Zq7Lr2", "Xw9Kp4Tn8Vb3Mc6Hd1Fs"),
      "",
      "Ticket #4412",
      "Name: Ada Morgan",
      "Phone: +44 20 7946 0018",
      "Card: 4111 1111 1111 1111",
      "Ada says her new token is " + k("gh", "p_", "R7tK2pQ9xW4mZ8vL1nB6cY3hJ5dF0sGa2Ue4"),
      "ssh amorgan@build-agent-02:~$ cat /home/amorgan/.netrc"
    ].join("\n");
  }

  // ---------------------------------------------------------------------------
  // Settings
  // ---------------------------------------------------------------------------
  function readTerms(el) {
    return el.value.split(/\r?\n/).map((t) => t.trim()).filter(Boolean);
  }

  customTermsEl.value = settings.customTerms.join("\n");
  allowTermsEl.value = settings.allowTerms.join("\n");
  redactLowEl.checked = settings.redactLow;
  if (settings.customTerms.length || settings.allowTerms.length) $("settings").open = true;

  let settingsTimer = 0;
  function settingsChanged() {
    clearTimeout(settingsTimer);
    settingsTimer = setTimeout(() => {
      settings.customTerms = readTerms(customTermsEl);
      settings.allowTerms = readTerms(allowTermsEl);
      store.set("customTerms", settings.customTerms);
      store.set("allowTerms", settings.allowTerms);
      scanNow();
    }, 250);
  }
  customTermsEl.addEventListener("input", settingsChanged);
  allowTermsEl.addEventListener("input", settingsChanged);
  redactLowEl.addEventListener("change", () => {
    settings.redactLow = redactLowEl.checked;
    store.set("redactLow", settings.redactLow);
    render();
  });

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------
  input.addEventListener("input", () => {
    status.textContent = "";
    scheduleScan();
  });
  $("sampleBtn").addEventListener("click", () => {
    input.value = sampleText();
    loadedName = "";
    fileStatus.textContent = "Sample loaded. Every value in it is fake.";
    choices.clear();
    scanNow();
  });
  $("clearBtn").addEventListener("click", () => {
    input.value = "";
    loadedName = "";
    fileInput.value = "";
    fileStatus.textContent = "";
    status.textContent = "";
    choices.clear();
    scanNow();
    input.focus();
  });
  fileInput.addEventListener("change", () => loadFile(fileInput.files && fileInput.files[0]));
  copyBtn.addEventListener("click", copy);
  downloadBtn.addEventListener("click", download);

  drop.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("dragging");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("dragging"));
  drop.addEventListener("drop", (event) => {
    event.preventDefault();
    drop.classList.remove("dragging");
    const file = event.dataTransfer && event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) loadFile(file);
  });

  scanNow();
})();
