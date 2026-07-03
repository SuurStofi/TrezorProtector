// TrezorProtector popup.
//
// All secret handling is click-driven from this browser-owned surface —
// web pages can neither see nor overlay it, which is the core defense
// against DOM-based extension clickjacking (DEF CON 33 / VU#516608).

"use strict";

const $ = (sel) => document.querySelector(sel);

const native = (payload) =>
  chrome.runtime.sendMessage({ type: "native", payload });
const nativeRaw = (payload) =>
  chrome.runtime.sendMessage({ type: "native-raw", payload });

let currentTabHost = "";
let entriesCache = []; // metadata only — never passwords
let totpTimer = null;

// --------------------------------------------------------------------------
// Views
// --------------------------------------------------------------------------

function show(view) {
  for (const id of ["view-install", "view-locked", "view-main"]) {
    $("#" + id).classList.toggle("hidden", id !== view);
  }
  $("#lock-btn").classList.toggle("hidden", view !== "view-main");
}

function toast(text, isError = false) {
  const el = $("#toast");
  el.textContent = text;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("hidden"), 2500);
}

async function refresh() {
  const status = await native({ cmd: "status" });
  if (status.host_missing) {
    show("view-install");
    return;
  }
  if (!status.unlocked) {
    show("view-locked");
    $("#unlock-status").textContent = status.vault_exists
      ? ""
      : "No vault found — create one first with `tp init`.";
    return;
  }
  show("view-main");
  await loadEntries($("#search").value);
}

// --------------------------------------------------------------------------
// Unlock flow (PIN matrix / passphrase relayed from the host)
// --------------------------------------------------------------------------

let pinBuffer = "";

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "host-event") return;
  if (msg.event === "button") {
    $("#unlock-status").textContent = "Confirm on your Trezor…";
  } else if (msg.event === "pin_request") {
    pinBuffer = "";
    renderPinDots();
    $("#pin-panel").classList.remove("hidden");
    $("#unlock-status").textContent = "Device asks for your PIN.";
  } else if (msg.event === "passphrase_request") {
    $("#passphrase-panel").classList.remove("hidden");
    $("#unlock-status").textContent = "Device asks for your passphrase.";
  }
});

function renderPinDots() {
  $("#pin-dots").textContent = "●".repeat(pinBuffer.length) || " ";
}

function wireUnlock() {
  $("#unlock-btn").addEventListener("click", async () => {
    $("#unlock-status").textContent = "Connecting to device…";
    $("#unlock-btn").disabled = true;
    const reply = await native({ cmd: "unlock" });
    $("#unlock-btn").disabled = false;
    $("#pin-panel").classList.add("hidden");
    $("#passphrase-panel").classList.add("hidden");
    if (reply.ok) {
      toast(`Unlocked — ${reply.entry_count} entries`);
      await refresh();
    } else {
      $("#unlock-status").textContent = reply.error || "Unlock failed.";
    }
  });

  for (const btn of document.querySelectorAll(".pin-grid button")) {
    btn.addEventListener("click", () => {
      if (pinBuffer.length < 9) pinBuffer += btn.dataset.pos;
      renderPinDots();
    });
  }
  $("#pin-back").addEventListener("click", () => {
    pinBuffer = pinBuffer.slice(0, -1);
    renderPinDots();
  });
  $("#pin-submit").addEventListener("click", () => {
    nativeRaw({ cmd: "pin", value: pinBuffer });
    pinBuffer = "";
    renderPinDots();
    $("#pin-panel").classList.add("hidden");
    $("#unlock-status").textContent = "Checking PIN…";
  });
  $("#pin-cancel").addEventListener("click", () => {
    nativeRaw({ cmd: "cancel" });
    $("#pin-panel").classList.add("hidden");
  });

  $("#pp-on-device").addEventListener("click", () => {
    nativeRaw({ cmd: "passphrase", value: "" });
    $("#passphrase-panel").classList.add("hidden");
    $("#unlock-status").textContent = "Enter the passphrase on the device…";
  });
  $("#pp-submit").addEventListener("click", () => {
    nativeRaw({ cmd: "passphrase", value: $("#pp-input").value });
    $("#pp-input").value = "";
    $("#passphrase-panel").classList.add("hidden");
  });
}

// --------------------------------------------------------------------------
// Entry list
// --------------------------------------------------------------------------

async function loadEntries(query) {
  const reply = await native({ cmd: "list", query: query || "" });
  if (!reply.ok) {
    if (reply.locked) await refresh();
    return;
  }
  entriesCache = reply.entries;

  // Entries matching the current site float to the top.
  const matches = (e) =>
    currentTabHost && e.url &&
    (hostnameLike(e.url) === currentTabHost ||
      currentTabHost.endsWith("." + hostnameLike(e.url)) ||
      hostnameLike(e.url).endsWith("." + currentTabHost));
  entriesCache.sort((a, b) => Number(matches(b)) - Number(matches(a)) ||
    a.name.localeCompare(b.name));

  const box = $("#entries");
  box.textContent = "";
  $("#entry-count").textContent = `${entriesCache.length} entries`;

  if (!entriesCache.length) {
    const empty = document.createElement("p");
    empty.className = "dim center-note";
    empty.textContent = "Nothing found.";
    box.appendChild(empty);
    return;
  }

  for (const e of entriesCache) {
    box.appendChild(renderEntry(e, matches(e)));
  }
}

function hostnameLike(url) {
  try { return new URL(url).hostname.toLowerCase(); }
  catch (_) {
    try { return new URL("https://" + url).hostname.toLowerCase(); }
    catch (_) { return ""; }
  }
}

function renderEntry(e, siteMatch) {
  const div = document.createElement("div");
  div.className = "entry" + (siteMatch ? " site-match" : "");

  const top = document.createElement("div");
  top.className = "top";
  const name = document.createElement("span");
  name.className = "name";
  name.textContent = e.name;
  const user = document.createElement("span");
  user.className = "user";
  user.textContent = e.username;
  top.append(name, user);

  const actions = document.createElement("div");
  actions.className = "actions";

  const fillBtn = document.createElement("button");
  fillBtn.textContent = "Fill";
  fillBtn.title = "Fill on the current page (top frame only)";
  fillBtn.addEventListener("click", () => doFill(e));

  const copyPw = document.createElement("button");
  copyPw.textContent = "Copy pass";
  copyPw.addEventListener("click", () => copySecret(e, "password"));

  const copyUser = document.createElement("button");
  copyUser.textContent = "Copy user";
  copyUser.addEventListener("click", () => copyText(e.username, false));

  actions.append(fillBtn, copyPw, copyUser);

  if (e.has_totp) {
    const totpBtn = document.createElement("button");
    totpBtn.textContent = "2FA code";
    totpBtn.addEventListener("click", () => showTotp(e, totpBtn, actions));
    actions.append(totpBtn);
  }

  div.append(top, actions);
  return div;
}

async function doFill(entry, confirmedMismatch = false) {
  const reply = await chrome.runtime.sendMessage({
    type: "fill",
    entryId: entry.id,
    confirmedMismatch,
  });
  if (reply.ok) {
    toast(`Filled '${entry.name}'`);
    window.close();
  } else if (reply.domain_mismatch) {
    askConfirm(
      `This entry is saved for “${reply.entry_host}” but the page is “${reply.tab_host}”. ` +
        "Filling on a look-alike site is how phishing steals passwords.",
      () => doFill(entry, true)
    );
  } else {
    toast(reply.error || "Fill failed", true);
    if (reply.locked) refresh();
  }
}

async function copySecret(entry, field) {
  const reply = await native({ cmd: "get", entry_id: entry.id });
  if (!reply.ok) {
    toast(reply.error || "Failed", true);
    if (reply.locked) refresh();
    return;
  }
  await copyText(reply[field], true);
}

async function copyText(text, sensitive) {
  try {
    await navigator.clipboard.writeText(text);
    if (sensitive) {
      chrome.runtime.sendMessage({ type: "schedule-clipboard-clear" });
      toast("Copied — clipboard clears in ~35 s");
    } else {
      toast("Copied");
    }
  } catch (_) {
    toast("Clipboard unavailable", true);
  }
}

async function showTotp(entry, btn, container) {
  const reply = await native({ cmd: "totp", entry_id: entry.id });
  if (!reply.ok) {
    toast(reply.error || "TOTP failed", true);
    return;
  }
  btn.classList.add("hidden");
  const code = document.createElement("button");
  code.className = "totp-code";
  code.title = "Click to copy";
  let remaining = reply.seconds_remaining;
  code.textContent = `${reply.code} · ${remaining}s`;
  code.addEventListener("click", () => copyText(code.textContent.split(" ")[0], true));
  container.append(code);

  clearInterval(totpTimer);
  totpTimer = setInterval(async () => {
    remaining -= 1;
    if (remaining <= 0) {
      const next = await native({ cmd: "totp", entry_id: entry.id });
      if (next.ok) {
        code.firstChild && (code.textContent = "");
        remaining = next.seconds_remaining;
        code.textContent = `${next.code} · ${remaining}s`;
        return;
      }
      clearInterval(totpTimer);
      code.remove();
      btn.classList.remove("hidden");
      return;
    }
    const [shown] = code.textContent.split(" ");
    code.textContent = `${shown} · ${remaining}s`;
  }, 1000);
}

// --------------------------------------------------------------------------
// Confirm overlay (domain mismatch)
// --------------------------------------------------------------------------

function askConfirm(text, onYes) {
  $("#confirm-text").textContent = text;
  $("#confirm-overlay").classList.remove("hidden");
  const done = () => {
    $("#confirm-overlay").classList.add("hidden");
    $("#confirm-yes").onclick = null;
    $("#confirm-no").onclick = null;
  };
  $("#confirm-yes").onclick = () => { done(); onYes(); };
  $("#confirm-no").onclick = done;
}

// --------------------------------------------------------------------------
// Generator
// --------------------------------------------------------------------------

function wireGenerator() {
  const regen = async () => {
    const passphrase = $("#gen-passphrase").checked;
    const reply = await native(
      passphrase
        ? { cmd: "generate", passphrase: true, words: 6 }
        : {
            cmd: "generate",
            length: Number($("#gen-length").value) || 20,
            symbols: $("#gen-symbols").checked,
          }
    );
    if (reply.ok) {
      $("#gen-output").textContent = reply.value;
      $("#gen-bits").textContent = `${Math.round(reply.bits)} bits`;
    }
  };
  $("#gen-new").addEventListener("click", regen);
  $("#generator").addEventListener("toggle", (e) => {
    if (e.target.open && !$("#gen-output").textContent) regen();
  });
  $("#gen-copy").addEventListener("click", () => {
    const value = $("#gen-output").textContent;
    if (value) copyText(value, true);
  });
}

// --------------------------------------------------------------------------
// Save-password banner
// --------------------------------------------------------------------------

async function refreshSaveBanner() {
  const pending = await chrome.runtime.sendMessage({ type: "get-pending-save" });
  const banner = $("#save-banner");
  if (!pending?.ok) {
    banner.classList.add("hidden");
    return;
  }
  const who = pending.username ? ` (${pending.username})` : "";
  $("#save-text").textContent = pending.existing_id
    ? `Update the password for “${pending.existing_name}”${who}?`
    : `Save the password for ${pending.host}${who} to your Trezor vault?`;
  $("#save-yes").textContent = pending.existing_id ? "Update entry" : "Save to vault";
  $("#save-status").textContent = "";
  banner.classList.remove("hidden");
}

function wireSaveBanner() {
  $("#save-yes").addEventListener("click", async () => {
    $("#save-yes").disabled = true;

    // Saving needs an unlocked vault; unlocking may pop up native Trezor
    // dialogs (connect / PIN) from the host, or the PIN panel here.
    const status = await native({ cmd: "status" });
    if (!status.unlocked) {
      $("#save-status").textContent = "Unlock first — confirm on your Trezor…";
      const unlock = await native({ cmd: "unlock" });
      if (!unlock.ok) {
        $("#save-status").textContent = unlock.error || "Unlock failed.";
        $("#save-yes").disabled = false;
        return;
      }
      await refresh();
    }

    const reply = await chrome.runtime.sendMessage({ type: "commit-pending-save" });
    $("#save-yes").disabled = false;
    if (reply.ok) {
      $("#save-banner").classList.add("hidden");
      toast("Saved to your Trezor vault");
      await loadEntries($("#search").value);
    } else {
      $("#save-status").textContent = reply.error || "Save failed.";
    }
  });

  $("#save-no").addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "dismiss-pending-save" });
    $("#save-banner").classList.add("hidden");
  });
}

// --------------------------------------------------------------------------
// Init
// --------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  wireUnlock();
  wireGenerator();
  wireSaveBanner();
  refreshSaveBanner();

  $("#search").addEventListener("input", () => loadEntries($("#search").value));
  $("#lock-btn").addEventListener("click", async () => {
    await native({ cmd: "lock" });
    show("view-locked");
    $("#unlock-status").textContent = "Locked.";
  });
  $("#autolock").addEventListener("change", async (e) => {
    await native({ cmd: "configure", autolock_minutes: Number(e.target.value) });
    chrome.storage.local.set({ autolock: e.target.value });
  });

  const stored = await chrome.storage.local.get("autolock");
  if (stored.autolock) {
    $("#autolock").value = stored.autolock;
    native({ cmd: "configure", autolock_minutes: Number(stored.autolock) });
  }

  const tabReply = await chrome.runtime.sendMessage({ type: "active-tab-host" });
  currentTabHost = tabReply?.host || "";

  await refresh();
});
