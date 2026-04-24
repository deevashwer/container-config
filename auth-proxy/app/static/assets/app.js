import {
  describeError,
  OwnerAuthBrowserClient,
  OwnerStateVault,
  parseOwnerStateText,
} from "./lib/owner-auth.js";

const client = new OwnerAuthBrowserClient("");
const vault = new OwnerStateVault("openclaw.auth-proxy.owner-state.v1");

const elements = {
  transportStatus: document.querySelector("#transport-status"),
  statusNote: document.querySelector("#status-note"),
  ownerStateFile: document.querySelector("#owner-state-file"),
  ownerStateJson: document.querySelector("#owner-state-json"),
  rememberStateToggle: document.querySelector("#remember-state-toggle"),
  loadJsonButton: document.querySelector("#load-json-button"),
  ownerSummary: document.querySelector("#owner-summary"),
  configAppName: document.querySelector("#config-app-name"),
  configChallengeTtl: document.querySelector("#config-challenge-ttl"),
  configOwnerKeyId: document.querySelector("#config-owner-key-id"),
  configWorkspacePath: document.querySelector("#config-workspace-path"),
  clearOwnerStateButton: document.querySelector("#clear-owner-state"),
  logoutSessionButton: document.querySelector("#logout-session-button"),
};

const state = {
  config: null,
  ownerState: null,
};

function setTransportState(label, transportState) {
  elements.transportStatus.textContent = label;
  elements.transportStatus.dataset.state = transportState;
}

function setStatusNote(message) {
  elements.statusNote.textContent = message;
}

function currentWorkspacePath() {
  return state.config?.openclaw_workspace_path || "/openclaw/";
}

function renderOwnerSummary(ownerState, config) {
  if (!ownerState) {
    elements.ownerSummary.dataset.state = "warning";
    elements.ownerSummary.innerHTML = `
      <p class="owner-summary-title">No owner key loaded</p>
      <p class="owner-summary-copy">
        Use the JSON created by <code>python_client/owner_auth_chat.py bootstrap --state-file ...</code>.
      </p>
    `;
    return;
  }

  const matches = !config?.owner_key_id || config.owner_key_id === ownerState.ownerKeyId;
  elements.ownerSummary.dataset.state = matches ? "ready" : "danger";
  elements.ownerSummary.innerHTML = `
    <p class="owner-summary-title">${matches ? "Owner key ready" : "Owner key mismatch"}</p>
    <p class="owner-summary-copy mono">${ownerState.ownerKeyId}</p>
    <p class="owner-summary-copy">
      ${ownerState.persisted ? "Saved in this browser." : "Held only for this browser session."}
    </p>
    <p class="owner-summary-copy">
      Bootstrap env keys: ${Object.keys(ownerState.bootstrapEnv || {}).join(", ") || "none"}
    </p>
  `;
}

function persistOwnerState(ownerState) {
  ownerState.persisted = elements.rememberStateToggle.checked;
  if (ownerState.persisted) {
    vault.save(ownerState);
    return;
  }
  vault.clear();
}

function clearOwnerState() {
  state.ownerState = null;
  vault.clear();
  elements.ownerStateJson.value = "";
  renderOwnerSummary(null, state.config);
}

async function unlockAndRedirect(ownerState, sourceLabel) {
  if (state.config?.owner_key_id && state.config.owner_key_id !== ownerState.ownerKeyId) {
    renderOwnerSummary(ownerState, state.config);
    setTransportState("Owner key mismatch", "danger");
    setStatusNote("The loaded owner key does not match the server configuration.");
    return;
  }

  persistOwnerState(ownerState);
  state.ownerState = ownerState;
  renderOwnerSummary(ownerState, state.config);
  setTransportState("Creating session", "warning");
  setStatusNote(`Signing the owner challenge from ${sourceLabel}.`);

  try {
    await client.login(ownerState);
    setTransportState("Session ready", "ready");
    setStatusNote("Proxy session created. Redirecting to OpenClaw.");
    window.location.assign(currentWorkspacePath());
  } catch (error) {
    setTransportState("Unlock failed", "danger");
    setStatusNote(describeError(error));
  }
}

async function loadSelectedFile() {
  const file = elements.ownerStateFile.files && elements.ownerStateFile.files[0];
  if (!file) {
    return;
  }
  try {
    const parsed = await parseOwnerStateText(await file.text());
    await unlockAndRedirect(parsed, "the selected owner state file");
  } catch (error) {
    setTransportState("Owner file rejected", "danger");
    setStatusNote(describeError(error));
  } finally {
    elements.ownerStateFile.value = "";
  }
}

async function loadPastedJson() {
  const text = elements.ownerStateJson.value.trim();
  if (!text) {
    setTransportState("Paste required", "warning");
    setStatusNote("Paste the owner state JSON before trying to unlock.");
    return;
  }
  try {
    const parsed = await parseOwnerStateText(text);
    await unlockAndRedirect(parsed, "the pasted JSON");
  } catch (error) {
    setTransportState("Pasted JSON rejected", "danger");
    setStatusNote(describeError(error));
  }
}

async function clearSession() {
  try {
    await client.logout();
    setTransportState("Session cleared", "warning");
    setStatusNote("The browser session was cleared.");
  } catch (error) {
    setTransportState("Session clear failed", "danger");
    setStatusNote(describeError(error));
  }
}

async function init() {
  elements.ownerStateFile.addEventListener("change", () => void loadSelectedFile());
  elements.loadJsonButton.addEventListener("click", () => void loadPastedJson());
  elements.clearOwnerStateButton.addEventListener("click", () => {
    clearOwnerState();
    setTransportState("Saved key cleared", "warning");
    setStatusNote("The saved owner key was removed from this browser.");
  });
  elements.logoutSessionButton.addEventListener("click", () => void clearSession());

  try {
    state.config = await client.loadPublicConfig();
    elements.configAppName.textContent = state.config.app_name;
    elements.configChallengeTtl.textContent = `${state.config.challenge_ttl_seconds}s`;
    elements.configOwnerKeyId.textContent = state.config.owner_key_id || "Not configured";
    elements.configWorkspacePath.textContent = currentWorkspacePath();
  } catch (error) {
    setTransportState("Proxy config failed", "danger");
    setStatusNote(describeError(error));
    return;
  }

  try {
    await client.getSession();
    setTransportState("Session ready", "ready");
    setStatusNote("Existing browser session found. Redirecting to OpenClaw.");
    window.location.assign(currentWorkspacePath());
    return;
  } catch {
    // No active session; continue to unlock screen.
  }

  const storedOwnerState = vault.restore();
  if (storedOwnerState) {
    try {
      renderOwnerSummary(storedOwnerState, state.config);
      setTransportState("Stored key found", "warning");
      setStatusNote("Trying the stored owner key automatically.");
      await unlockAndRedirect(storedOwnerState, "the stored browser key");
      return;
    } catch (error) {
      vault.clear();
      setTransportState("Stored key rejected", "danger");
      setStatusNote(describeError(error));
    }
  }

  renderOwnerSummary(null, state.config);
  setTransportState("Ready to unlock", "ready");
  setStatusNote("Choose the owner state file to enter the OpenClaw chat.");
}

init().catch((error) => {
  setTransportState("Startup failed", "danger");
  setStatusNote(describeError(error));
});
