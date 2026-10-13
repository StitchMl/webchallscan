"use strict";

const button = document.getElementById("capture");
const endpoint = document.getElementById("endpoint");
const token = document.getElementById("token");
const status = document.getElementById("status");

function showStatus(message, failed = false) {
  status.textContent = message;
  status.className = failed ? "error" : "success";
}

button.addEventListener("click", async () => {
  button.disabled = true;
  showStatus("Capturing…");
  try {
    const response = await chrome.runtime.sendMessage({
      type: "webchallscan.capture-session.v1",
      endpoint: endpoint.value.trim(),
      token: token.value.trim()
    });
    token.value = "";
    if (!response || !response.ok) {
      throw new Error(response?.error || "Extension service worker did not respond.");
    }
    showStatus("Session sent.");
  } catch (error) {
    token.value = "";
    showStatus(error.message, true);
  } finally {
    button.disabled = false;
  }
});
