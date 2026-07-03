// Offscreen document: the only place an MV3 extension can write the
// clipboard without an open popup. Used solely to blank it after the
// auto-clear delay.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "offscreen-clear-clipboard") return;
  const sink = document.getElementById("sink");
  sink.value = " ";
  sink.select();
  try {
    document.execCommand("copy");
  } catch (_) {}
});
