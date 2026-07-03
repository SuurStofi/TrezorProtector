// TrezorProtector credential-capture content script.
//
// Security posture: this script injects NOTHING into the page — no
// dropdowns, no buttons, no overlays — so the DOM-clickjacking attack class
// against password-manager extensions has no surface here. It only
// *observes* form submissions and forwards the credentials to the service
// worker, which asks for an explicit user decision in the browser-owned
// popup before anything is saved. Runs in the top frame only.

(() => {
  "use strict";

  let lastSent = 0;

  function visible(el) {
    return el && el.offsetParent !== null && !el.disabled;
  }

  function findUsername(form, pwField) {
    const candidates = [
      ...form.querySelectorAll(
        'input[autocomplete=username], input[type=email], input[type=text], input[name*="user" i], input[name*="mail" i], input[name*="login" i]'
      ),
    ].filter((el) => visible(el) && el.value);
    // Prefer the last matching field that precedes the password field.
    let best = null;
    for (const el of candidates) {
      if (
        !pwField ||
        el.compareDocumentPosition(pwField) & Node.DOCUMENT_POSITION_FOLLOWING
      ) {
        best = el;
      }
    }
    return best || candidates[0] || null;
  }

  function capture(form) {
    if (!(form instanceof HTMLFormElement)) return;
    const pwField = [...form.querySelectorAll("input[type=password]")].find(
      (el) => visible(el) && el.value
    );
    if (!pwField) return;
    // Ignore likely sign-up / change-password forms with 2+ password fields
    // holding different values (we can't tell which one is "the" password).
    const pwValues = [...form.querySelectorAll("input[type=password]")]
      .map((el) => el.value)
      .filter(Boolean);
    if (new Set(pwValues).size > 1) return;

    // Debounce double submits.
    const now = Date.now();
    if (now - lastSent < 2000) return;
    lastSent = now;

    const userField = findUsername(form, pwField);
    try {
      chrome.runtime.sendMessage({
        type: "creds-submitted",
        url: location.href,
        username: userField ? userField.value : "",
        password: pwField.value,
      });
    } catch (_) {
      // Extension got reloaded; nothing to do.
    }
  }

  document.addEventListener(
    "submit",
    (e) => capture(e.target),
    true // capture phase: fires even if the page cancels the event later
  );

  // SPA logins that bypass <form> submit: catch clicks on submit-ish buttons
  // inside a form.
  document.addEventListener(
    "click",
    (e) => {
      const btn = e.target instanceof Element &&
        e.target.closest('button[type=submit], input[type=submit]');
      if (btn && btn.form) capture(btn.form);
    },
    true
  );
})();
