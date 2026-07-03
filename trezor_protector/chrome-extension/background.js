// TrezorProtector service worker.
//
// Owns the native-messaging port to tp-host and routes messages between the
// popup and the host. Security invariants enforced here:
//
//  * No UI is ever injected into web pages, and there is no content script —
//    this is the mitigation for the DOM-based extension clickjacking class
//    (DEF CON 33 / VU#516608): a page cannot overlay or spoof what it
//    cannot see, and filling requires a click inside the browser-owned
//    popup, which pages cannot clickjack.
//  * Fill runs in the TOP frame only (allFrames: false), so credentials
//    never land in a third-party iframe.
//  * The tab's registrable domain must match the entry's URL, otherwise the
//    popup asks the user for explicit confirmation.
//  * Passwords are fetched from the host one entry at a time and are not
//    cached anywhere in the extension.

const HOST_NAME = "com.trezorprotector";
const CLIPBOARD_CLEAR_SECONDS = 35;

let port = null;
let nextId = 1;
const pending = new Map(); // id -> {resolve}

function connect() {
  if (port) return port;
  port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener(onHostMessage);
  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError?.message || "host disconnected";
    for (const { resolve } of pending.values()) {
      resolve({ ok: false, error: err, host_missing: true });
    }
    pending.clear();
    port = null;
  });
  return port;
}

function onHostMessage(msg) {
  // Interaction events (PIN, passphrase, button) go to the popup.
  if (msg.event) {
    chrome.runtime.sendMessage({ type: "host-event", event: msg.event, id: msg.id })
      .catch(() => {
        // Popup closed mid-unlock: cancel so the host isn't stuck waiting.
        try { port?.postMessage({ cmd: "cancel" }); } catch (_) {}
      });
    return;
  }
  const entry = pending.get(msg.id);
  if (entry) {
    pending.delete(msg.id);
    entry.resolve(msg);
  }
}

function callHost(payload) {
  return new Promise((resolve) => {
    let p;
    try {
      p = connect();
    } catch (e) {
      resolve({ ok: false, error: String(e), host_missing: true });
      return;
    }
    const id = nextId++;
    pending.set(id, { resolve });
    try {
      p.postMessage({ ...payload, id });
    } catch (e) {
      pending.delete(id);
      resolve({ ok: false, error: String(e), host_missing: true });
    }
  });
}

// Raw sends without a pending reply slot (PIN/passphrase answers, cancel).
function sendToHost(payload) {
  try {
    connect().postMessage(payload);
  } catch (_) {}
}

// --------------------------------------------------------------------------
// Domain matching (fill safety)
// --------------------------------------------------------------------------

function hostnameOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (_) {
    // Stored URLs may lack a scheme.
    try {
      return new URL("https://" + url).hostname.toLowerCase();
    } catch (_) {
      return "";
    }
  }
}

// True when both hostnames share a registrable parent (login.example.com
// matches example.com) — conservative approximation without a PSL table.
function domainsMatch(tabUrl, entryUrl) {
  const a = hostnameOf(tabUrl);
  const b = hostnameOf(entryUrl);
  if (!a || !b) return false;
  return a === b || a.endsWith("." + b) || b.endsWith("." + a);
}

// --------------------------------------------------------------------------
// Fill (runs in the page, top frame only)
// --------------------------------------------------------------------------

function fillInPage(username, password) {
  const visible = (el) =>
    el && el.offsetParent !== null && !el.disabled && !el.readOnly;

  const setValue = (el, value) => {
    // Go through the native setter so React/Vue controlled inputs update.
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    desc.set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const pwField = [...document.querySelectorAll("input[type=password]")].find(visible);

  if (username) {
    const candidates = [
      ...document.querySelectorAll(
        'input[autocomplete=username], input[type=email], input[type=text], input[name*="user" i], input[name*="mail" i], input[name*="login" i]'
      ),
    ].filter(visible);
    let userField = null;
    if (pwField) {
      // Last matching field that appears before the password field.
      for (const el of candidates) {
        if (el.compareDocumentPosition(pwField) & Node.DOCUMENT_POSITION_FOLLOWING) {
          userField = el;
        }
      }
    }
    userField = userField || candidates[0];
    if (userField) setValue(userField, username);
  }

  if (password && pwField) setValue(pwField, password);
  return { filled_password: Boolean(password && pwField) };
}

async function fillCredentials(entryId, confirmedMismatch) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !/^https?:/i.test(tab.url || "")) {
    return { ok: false, error: "no fillable page in the active tab" };
  }

  const details = await callHost({ cmd: "get", entry_id: entryId });
  if (!details.ok) return details;

  if (details.url && !domainsMatch(tab.url, details.url) && !confirmedMismatch) {
    return {
      ok: false,
      domain_mismatch: true,
      tab_host: hostnameOf(tab.url),
      entry_host: hostnameOf(details.url),
    };
  }

  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: false },
    func: fillInPage,
    args: [details.username || "", details.password || ""],
  });
  const outcome = results?.[0]?.result;
  if (!outcome?.filled_password) {
    return { ok: false, error: "no visible password field on the page" };
  }
  return { ok: true };
}

// --------------------------------------------------------------------------
// Clipboard auto-clear via offscreen document
// --------------------------------------------------------------------------

async function ensureOffscreen() {
  const has = await chrome.offscreen.hasDocument?.();
  if (!has) {
    await chrome.offscreen.createDocument({
      url: "offscreen.html",
      reasons: ["CLIPBOARD"],
      justification: "Clear the clipboard after a copied password expires.",
    });
  }
}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === "clear-clipboard") {
    try {
      await ensureOffscreen();
      chrome.runtime.sendMessage({ type: "offscreen-clear-clipboard" }).catch(() => {});
    } catch (_) {}
  }
});

// --------------------------------------------------------------------------
// Save-password detection
//
// The content script reports submitted credentials; we hold them in
// chrome.storage.session (memory-only, wiped when the browser closes) and
// badge the icon. Nothing is written to the vault until the user clicks
// Save in the popup.
// --------------------------------------------------------------------------

async function pendingKey(tabId) {
  return `pending-save-${tabId}`;
}

async function getPending(tabId) {
  const key = await pendingKey(tabId);
  const data = await chrome.storage.session.get(key);
  return data[key] || null;
}

async function setPending(tabId, value) {
  const key = await pendingKey(tabId);
  if (value) {
    await chrome.storage.session.set({ [key]: value });
    chrome.action.setBadgeBackgroundColor({ color: "#27b06c", tabId });
    chrome.action.setBadgeText({ text: "＋", tabId });
  } else {
    await chrome.storage.session.remove(key);
    chrome.action.setBadgeText({ text: "", tabId });
  }
}

async function onCredsSubmitted(msg, tabId) {
  const host = hostnameOf(msg.url);
  if (!host || !msg.password) return;

  // If the vault is unlocked, figure out whether this is new, changed,
  // or already stored. When locked we still offer to save (state unknown).
  let existing = null;
  let changed = true;
  const status = await callHost({ cmd: "status" });
  if (status.host_missing) return;
  if (status.unlocked) {
    const list = await callHost({ cmd: "list", query: "" });
    if (list.ok) {
      const matches = list.entries.filter(
        (e) =>
          e.url &&
          domainsMatch(msg.url, e.url) &&
          (!msg.username || !e.username || e.username === msg.username)
      );
      if (matches.length) {
        existing = matches.find((e) => e.username === msg.username) || matches[0];
        const details = await callHost({ cmd: "get", entry_id: existing.id });
        if (details.ok && details.password === msg.password) changed = false;
      }
    }
  }
  if (!changed) return; // identical password already in the vault

  await setPending(tabId, {
    host,
    url: msg.url,
    username: msg.username,
    password: msg.password,
    existing_id: existing ? existing.id : null,
    existing_name: existing ? existing.name : null,
    ts: Date.now(),
  });
}

chrome.tabs.onRemoved.addListener((tabId) => setPending(tabId, null));

// --------------------------------------------------------------------------
// Popup API
// --------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg.type) {
      case "creds-submitted":
        if (sender.tab?.id != null) await onCredsSubmitted(msg, sender.tab.id);
        sendResponse({ ok: true });
        break;
      case "get-pending-save": {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const pending = tab?.id != null ? await getPending(tab.id) : null;
        // Never hand the captured password itself to the popup — it only
        // needs the metadata to render the banner.
        sendResponse(
          pending
            ? {
                ok: true,
                host: pending.host,
                username: pending.username,
                existing_id: pending.existing_id,
                existing_name: pending.existing_name,
              }
            : { ok: false }
        );
        break;
      }
      case "commit-pending-save": {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        const pending = tab?.id != null ? await getPending(tab.id) : null;
        if (!pending) {
          sendResponse({ ok: false, error: "nothing to save" });
          break;
        }
        let reply;
        if (pending.existing_id) {
          reply = await callHost({
            cmd: "update_password",
            entry_id: pending.existing_id,
            password: pending.password,
          });
        } else {
          reply = await callHost({
            cmd: "add",
            name: pending.host,
            username: pending.username,
            url: pending.url,
            password: pending.password,
          });
        }
        if (reply.ok) await setPending(tab.id, null);
        sendResponse(reply);
        break;
      }
      case "dismiss-pending-save": {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id != null) await setPending(tab.id, null);
        sendResponse({ ok: true });
        break;
      }
      case "native":
        sendResponse(await callHost(msg.payload));
        break;
      case "native-raw": // PIN / passphrase answers during unlock
        sendToHost(msg.payload);
        sendResponse({ ok: true });
        break;
      case "fill":
        sendResponse(await fillCredentials(msg.entryId, msg.confirmedMismatch));
        break;
      case "schedule-clipboard-clear":
        chrome.alarms.create("clear-clipboard", {
          delayInMinutes: CLIPBOARD_CLEAR_SECONDS / 60,
        });
        sendResponse({ ok: true });
        break;
      case "active-tab-host": {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        sendResponse({ ok: true, host: hostnameOf(tab?.url || "") });
        break;
      }
      default:
        // offscreen-clear-clipboard is handled by the offscreen page itself.
        break;
    }
  })();
  return true; // async response
});
