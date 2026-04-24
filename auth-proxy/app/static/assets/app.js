import {
  BrowserSecretStore,
  PasskeyAuthBrowserClient,
  describeError,
  formatDateTime,
  supportsPasskeys,
} from "./lib/passkey-auth.js";

const client = new PasskeyAuthBrowserClient("");
const secretStore = new BrowserSecretStore("openclaw.auth-proxy.keystore.v2");

const elements = {
  transportStatus: document.querySelector("#transport-status"),
  statusNote: document.querySelector("#status-note"),
  continuityNote: document.querySelector("#continuity-note"),
  primaryPasskeyButton: document.querySelector("#primary-passkey-button"),
  anthropicApiKey: document.querySelector("#anthropic-api-key"),
  setupSummary: document.querySelector("#setup-summary"),
  configAppName: document.querySelector("#config-app-name"),
  configChallengeTtl: document.querySelector("#config-challenge-ttl"),
  configPasskeyState: document.querySelector("#config-passkey-state"),
  configPasskeyCount: document.querySelector("#config-passkey-count"),
  configWorkspacePath: document.querySelector("#config-workspace-path"),
  passkeySupport: document.querySelector("#passkey-support"),
  localVaultStatus: document.querySelector("#local-vault-status"),
  configContinuityState: document.querySelector("#config-continuity-state"),
  localVerifiedTlsKey: document.querySelector("#local-verified-tls-key"),
  localVerifiedHpkeKey: document.querySelector("#local-verified-hpke-key"),
  clearLocalVaultButton: document.querySelector("#clear-local-vault"),
  logoutSessionButton: document.querySelector("#logout-session-button"),
};

function parseLocalVerifierExpectation() {
  const params = new URLSearchParams(window.location.search);
  const tlsPublicKey = params.get("local_verified_tls_public_key") || "";
  const hpkePublicKey = params.get("local_verified_hpke_public_key") || "";
  const continuityGap = params.get("local_verifier_gap") === "1";
  if (!tlsPublicKey && !hpkePublicKey && !continuityGap) {
    return null;
  }
  return {
    tlsPublicKey,
    hpkePublicKey,
    continuityGap,
  };
}

const state = {
  config: null,
  vaultMeta: null,
  passkeySupported: supportsPasskeys(),
  localVerifier: parseLocalVerifierExpectation(),
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

function typedBootstrapEnv() {
  const apiKey = elements.anthropicApiKey.value.trim();
  if (!apiKey) {
    return {};
  }
  return {
    ANTHROPIC_API_KEY: apiKey,
  };
}

async function effectiveBootstrapEnv() {
  const savedEnv = state.vaultMeta ? await secretStore.load() : {};
  return {
    ...savedEnv,
    ...typedBootstrapEnv(),
  };
}

function actionMode() {
  if (!state.config) {
    return "loading";
  }
  return state.config.initialization_available ? "initialize" : "authenticate";
}

function renderSupportState() {
  elements.passkeySupport.textContent = state.passkeySupported ? "Supported" : "Unavailable";
  elements.passkeySupport.dataset.state = state.passkeySupported ? "ready" : "danger";
}

function renderVaultStatus() {
  if (!state.vaultMeta) {
    elements.localVaultStatus.textContent = "Not stored on this browser";
    elements.localVaultStatus.dataset.state = "warning";
    return;
  }
  elements.localVaultStatus.textContent = `Saved ${formatDateTime(state.vaultMeta.savedAt)}`;
  elements.localVaultStatus.dataset.state = "ready";
}

function renderContinuityHint() {
  if (!state.localVerifier) {
    elements.continuityNote.hidden = true;
    elements.configContinuityState.textContent = "None";
    elements.localVerifiedTlsKey.textContent = "-";
    elements.localVerifiedHpkeKey.textContent = "-";
    return;
  }

  elements.continuityNote.hidden = false;
  elements.continuityNote.innerHTML = `
    <strong>Local Python verifier handoff</strong><br />
    This page was opened from a locally verified launch center. The expected attested keys were carried
    forward into the URL so you can see what Python verified first. This browser page is not yet
    cryptographically confirming that continuity on its own.
  `;
  elements.configContinuityState.textContent = state.localVerifier.continuityGap
    ? "Carried from local verifier only"
    : "Provided";
  elements.localVerifiedTlsKey.textContent = state.localVerifier.tlsPublicKey || "Unavailable";
  elements.localVerifiedHpkeKey.textContent = state.localVerifier.hpkePublicKey || "Unavailable";
}

function renderSummary() {
  if (!state.config) {
    elements.setupSummary.dataset.state = "warning";
    elements.setupSummary.innerHTML = `
      <p class="owner-summary-title">Loading gateway status</p>
      <p class="owner-summary-copy">Checking whether this enclave has already been claimed.</p>
    `;
    return;
  }

  if (state.config.initialization_available) {
    elements.setupSummary.dataset.state = "warning";
    elements.setupSummary.innerHTML = `
      <p class="owner-summary-title">Enclave initialization</p>
      <p class="owner-summary-copy">
        The first user can claim this enclave by entering <code>ANTHROPIC_API_KEY</code> if bootstrap needs it
        and approving a passkey. After that, initialization is closed and only that passkey can unlock it.
      </p>
    `;
    return;
  }

  if (state.vaultMeta) {
    elements.setupSummary.dataset.state = "ready";
    elements.setupSummary.innerHTML = `
      <p class="owner-summary-title">Passkey and local vault are ready</p>
      <p class="owner-summary-copy">
        This browser can approve the saved passkey and reuse the stored bootstrap env automatically.
      </p>
      <p class="owner-summary-copy">
        Stored env keys: ${(state.vaultMeta.bootstrapKeys || []).join(", ") || "none"}
      </p>
    `;
    return;
  }

  elements.setupSummary.dataset.state = "warning";
  elements.setupSummary.innerHTML = `
    <p class="owner-summary-title">Enclave already claimed</p>
    <p class="owner-summary-copy">
      Approve the passkey to enter. If this browser should also remember the bootstrap key, enter
      <code>ANTHROPIC_API_KEY</code> once before unlocking.
    </p>
  `;
}

function renderPrimaryButton() {
  if (!state.config) {
    elements.primaryPasskeyButton.textContent = "Checking gateway";
    elements.primaryPasskeyButton.disabled = true;
    return;
  }
  if (actionMode() === "initialize") {
    elements.primaryPasskeyButton.textContent = "Initialize enclave and enter OpenClaw";
  } else if (state.vaultMeta) {
    elements.primaryPasskeyButton.textContent = "Approve passkey and enter OpenClaw";
  } else {
    elements.primaryPasskeyButton.textContent = "Approve passkey and save this browser";
  }
  elements.primaryPasskeyButton.disabled = !state.passkeySupported;
}

function renderConfig() {
  elements.configAppName.textContent = state.config?.app_name || "Loading";
  elements.configChallengeTtl.textContent = state.config ? `${state.config.challenge_ttl_seconds}s` : "-";
  elements.configPasskeyState.textContent = state.config
    ? state.config.ownership_claimed
      ? "Claimed"
      : "Unclaimed"
    : "-";
  elements.configPasskeyCount.textContent = state.config ? String(state.config.passkey_count) : "-";
  elements.configWorkspacePath.textContent = currentWorkspacePath();
}

function render() {
  renderSupportState();
  renderVaultStatus();
  renderContinuityHint();
  renderSummary();
  renderPrimaryButton();
  renderConfig();
}

async function refreshConfig() {
  state.config = await client.loadPublicConfig();
  render();
}

async function saveVaultIfNeeded(bootstrapEnv) {
  if (!bootstrapEnv || Object.keys(bootstrapEnv).length === 0) {
    return;
  }
  state.vaultMeta = await secretStore.save(bootstrapEnv);
  render();
}

async function completePasskeyFlow({ auto = false } = {}) {
  if (!state.config) {
    return;
  }
  if (!state.passkeySupported) {
    setTransportState("Passkey unavailable", "danger");
    setStatusNote("This browser cannot use passkeys in the current context.");
    return;
  }

  const bootstrapEnv = await effectiveBootstrapEnv();
  const setupMode = actionMode() === "initialize";
  try {
    setTransportState(setupMode ? "Initializing enclave" : "Waiting for passkey", "warning");
    if (setupMode) {
      setStatusNote("Approve the new passkey to claim this enclave.");
      await client.initializeGateway(bootstrapEnv);
    } else {
      setStatusNote(auto ? "Trying the saved passkey automatically." : "Approve the passkey to unlock.");
      await client.authenticatePasskey(bootstrapEnv);
    }

    await saveVaultIfNeeded(bootstrapEnv);
    await refreshConfig();
    setTransportState("Session ready", "ready");
    setStatusNote("Proxy session created. Redirecting to OpenClaw.");
    window.location.assign(currentWorkspacePath());
  } catch (error) {
    try {
      await refreshConfig();
    } catch {
      // Keep the earlier state if refreshing config fails.
    }
    if (auto && error?.name === "NotAllowedError") {
      setTransportState("Passkey approval needed", "warning");
      setStatusNote("Approve the passkey to continue.");
      return;
    }
    setTransportState(setupMode ? "Initialization failed" : "Passkey unlock failed", "danger");
    setStatusNote(describeError(error));
  }
}

async function clearLocalVault() {
  try {
    await secretStore.clear();
    state.vaultMeta = null;
    elements.anthropicApiKey.value = "";
    render();
    setTransportState("Local vault cleared", "warning");
    setStatusNote("This browser will ask for the bootstrap key again if the upstream needs it.");
  } catch (error) {
    setTransportState("Clear failed", "danger");
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
  elements.primaryPasskeyButton.addEventListener("click", () => void completePasskeyFlow());
  elements.clearLocalVaultButton.addEventListener("click", () => void clearLocalVault());
  elements.logoutSessionButton.addEventListener("click", () => void clearSession());

  try {
    await refreshConfig();
  } catch (error) {
    setTransportState("Proxy config failed", "danger");
    setStatusNote(describeError(error));
    render();
    return;
  }

  try {
    await client.getSession();
    setTransportState("Session ready", "ready");
    setStatusNote("Existing browser session found. Redirecting to OpenClaw.");
    window.location.assign(currentWorkspacePath());
    return;
  } catch {
    // No active session; continue.
  }

  state.vaultMeta = await secretStore.metadata();
  render();

  if (state.vaultMeta && state.config?.ownership_claimed && state.passkeySupported) {
    await completePasskeyFlow({ auto: true });
    return;
  }

  if (!state.passkeySupported) {
    setTransportState("Passkey unavailable", "danger");
    setStatusNote("Use a secure browser context with passkey support to unlock this gateway.");
    return;
  }

  setTransportState("Ready", "ready");
  if (state.config?.initialization_available) {
    setStatusNote("Enter ANTHROPIC_API_KEY once if needed, then claim the enclave with a passkey.");
  } else if (state.vaultMeta) {
    setStatusNote("Approve the saved passkey to continue.");
  } else {
    setStatusNote("Approve the passkey to unlock. Enter ANTHROPIC_API_KEY once on this browser if the upstream needs it.");
  }
}

init().catch((error) => {
  setTransportState("Startup failed", "danger");
  setStatusNote(describeError(error));
});
