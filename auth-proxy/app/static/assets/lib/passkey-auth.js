const enc = new TextEncoder();
const dec = new TextDecoder();

function base64urlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(value) {
  const padding = "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + padding);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function responseError(status, payloadText) {
  const error = new Error(payloadText || `request failed with status ${status}`);
  error.status = status;
  return error;
}

function normalizeBootstrapEnv(rawEnv) {
  if (!rawEnv || typeof rawEnv !== "object" || Array.isArray(rawEnv)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(rawEnv)
      .map(([key, value]) => [String(key), String(value ?? "").trim()])
      .filter(([, value]) => value),
  );
}

function toCreationOptions(publicKey) {
  return {
    ...publicKey,
    challenge: base64urlDecode(publicKey.challenge),
    user: {
      ...publicKey.user,
      id: base64urlDecode(publicKey.user.id),
    },
    excludeCredentials: (publicKey.excludeCredentials || []).map((item) => ({
      ...item,
      id: base64urlDecode(item.id),
    })),
  };
}

function toRequestOptions(publicKey) {
  return {
    ...publicKey,
    challenge: base64urlDecode(publicKey.challenge),
    allowCredentials: (publicKey.allowCredentials || []).map((item) => ({
      ...item,
      id: base64urlDecode(item.id),
    })),
  };
}

function serializeCredential(credential) {
  const payload = {
    id: credential.id || base64urlEncode(new Uint8Array(credential.rawId)),
    rawId: base64urlEncode(new Uint8Array(credential.rawId)),
    type: credential.type,
    response: {
      clientDataJSON: base64urlEncode(new Uint8Array(credential.response.clientDataJSON)),
    },
  };

  if ("attestationObject" in credential.response) {
    payload.response.attestationObject = base64urlEncode(new Uint8Array(credential.response.attestationObject));
    return payload;
  }

  payload.response.authenticatorData = base64urlEncode(new Uint8Array(credential.response.authenticatorData));
  payload.response.signature = base64urlEncode(new Uint8Array(credential.response.signature));
  payload.response.userHandle = credential.response.userHandle
    ? base64urlEncode(new Uint8Array(credential.response.userHandle))
    : null;
  return payload;
}

export function supportsPasskeys() {
  return (
    typeof window !== "undefined" &&
    window.isSecureContext &&
    !!window.PublicKeyCredential &&
    !!navigator.credentials?.create &&
    !!navigator.credentials?.get
  );
}

export function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

export function formatDateTime(value) {
  if (!value) {
    return "-";
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf())) {
    return String(value);
  }
  return parsed.toLocaleString();
}

function maybeExtractJsonDetail(message) {
  if (!message || typeof message !== "string" || !message.trim().startsWith("{")) {
    return null;
  }
  try {
    const parsed = JSON.parse(message);
    if (typeof parsed?.detail === "string") {
      return parsed.detail;
    }
  } catch {
    return null;
  }
  return null;
}

export function describeError(error) {
  if (!error) {
    return "unknown error";
  }
  if (typeof error === "string") {
    return error;
  }
  if (error?.name === "NotAllowedError") {
    return "Passkey approval was cancelled or timed out.";
  }
  if (error?.name === "InvalidStateError") {
    return "This enclave has already been initialized.";
  }
  const jsonDetail = maybeExtractJsonDetail(error?.message);
  if (jsonDetail) {
    return jsonDetail;
  }
  if (error?.message) {
    return error.message;
  }
  return String(error);
}

export class BrowserSecretStore {
  constructor(dbName = "openclaw.auth-proxy.keystore.v2", storeName = "vault") {
    this.dbName = dbName;
    this.storeName = storeName;
    this.dbPromise = null;
  }

  async open() {
    if (!("indexedDB" in window)) {
      throw new Error("This browser does not expose IndexedDB for local secret storage.");
    }
    if (!this.dbPromise) {
      this.dbPromise = new Promise((resolve, reject) => {
        const request = window.indexedDB.open(this.dbName, 1);
        request.onupgradeneeded = () => {
          if (!request.result.objectStoreNames.contains(this.storeName)) {
            request.result.createObjectStore(this.storeName);
          }
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error("Failed to open the local vault."));
      });
    }
    return this.dbPromise;
  }

  async get(key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, "readonly");
      const request = transaction.objectStore(this.storeName).get(key);
      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error || new Error(`Failed to read ${key} from the local vault.`));
    });
  }

  async put(key, value) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, "readwrite");
      const request = transaction.objectStore(this.storeName).put(value, key);
      request.onsuccess = () => resolve(value);
      request.onerror = () => reject(request.error || new Error(`Failed to write ${key} to the local vault.`));
    });
  }

  async delete(key) {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(this.storeName, "readwrite");
      const request = transaction.objectStore(this.storeName).delete(key);
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error || new Error(`Failed to delete ${key} from the local vault.`));
    });
  }

  async metadata() {
    return (await this.get("vaultMeta")) || null;
  }

  async save(bootstrapEnv) {
    const normalized = normalizeBootstrapEnv(bootstrapEnv);
    const bundle = {
      bootstrapEnv: normalized,
    };
    const key = await crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt", "decrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = enc.encode(JSON.stringify(bundle));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));

    await this.put("vaultKey", key);
    await this.put("vaultCiphertext", {
      ciphertext: base64urlEncode(ciphertext),
      iv: base64urlEncode(iv),
    });
    await this.put("vaultMeta", {
      version: 2,
      bootstrapKeys: Object.keys(normalized),
      savedAt: new Date().toISOString(),
    });
    return this.metadata();
  }

  async load() {
    const [key, sealedPayload] = await Promise.all([this.get("vaultKey"), this.get("vaultCiphertext")]);
    if (!key || !sealedPayload?.ciphertext || !sealedPayload?.iv) {
      return {};
    }
    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: base64urlDecode(sealedPayload.iv),
      },
      key,
      base64urlDecode(sealedPayload.ciphertext),
    );
    const bundle = JSON.parse(dec.decode(decrypted));
    return normalizeBootstrapEnv(bundle.bootstrapEnv);
  }

  async clear() {
    await Promise.all([
      this.delete("vaultKey"),
      this.delete("vaultCiphertext"),
      this.delete("vaultMeta"),
    ]);
  }
}

export class PasskeyAuthBrowserClient {
  constructor(baseUrl = "") {
    this.baseUrl = baseUrl;
    this.publicConfig = null;
  }

  async loadPublicConfig() {
    const response = await fetch(`${this.baseUrl}/api/public/config`, {
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    this.publicConfig = await response.json();
    return this.publicConfig;
  }

  async getSession() {
    const response = await fetch(`${this.baseUrl}/api/private/session`, {
      method: "GET",
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    return response.json();
  }

  async logout() {
    const response = await fetch(`${this.baseUrl}/api/private/session/logout`, {
      method: "POST",
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    return response.json();
  }

  async beginInitialization() {
    const response = await fetch(`${this.baseUrl}/api/public/init/options`, {
      method: "POST",
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    return response.json();
  }

  async finishInitialization({ challengeId, credential, bootstrapEnv }) {
    const response = await fetch(`${this.baseUrl}/api/public/init/finish`, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        challenge_id: challengeId,
        credential,
        bootstrap_env: normalizeBootstrapEnv(bootstrapEnv),
      }),
    });
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    return response.json();
  }

  async beginAuthentication() {
    const response = await fetch(`${this.baseUrl}/api/public/passkeys/authenticate/options`, {
      method: "POST",
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    return response.json();
  }

  async finishAuthentication({ challengeId, credential, bootstrapEnv }) {
    const response = await fetch(`${this.baseUrl}/api/public/passkeys/authenticate/finish`, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        challenge_id: challengeId,
        credential,
        bootstrap_env: normalizeBootstrapEnv(bootstrapEnv),
      }),
    });
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    return response.json();
  }

  async initializeGateway(bootstrapEnv = {}) {
    if (!supportsPasskeys()) {
      throw new Error("This browser does not support passkeys in the current context.");
    }
    const options = await this.beginInitialization();
    const credential = await navigator.credentials.create({
      publicKey: toCreationOptions(options.public_key),
    });
    if (!credential || credential.type !== "public-key" || !credential.rawId) {
      throw new Error("Enclave initialization was cancelled.");
    }
    return this.finishInitialization({
      challengeId: options.challenge_id,
      credential: serializeCredential(credential),
      bootstrapEnv,
    });
  }

  async authenticatePasskey(bootstrapEnv = {}) {
    if (!supportsPasskeys()) {
      throw new Error("This browser does not support passkeys in the current context.");
    }
    const options = await this.beginAuthentication();
    const credential = await navigator.credentials.get({
      publicKey: toRequestOptions(options.public_key),
    });
    if (!credential || credential.type !== "public-key" || !credential.rawId) {
      throw new Error("Passkey approval was cancelled.");
    }
    return this.finishAuthentication({
      challengeId: options.challenge_id,
      credential: serializeCredential(credential),
      bootstrapEnv,
    });
  }
}
