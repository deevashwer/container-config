const enc = new TextEncoder();

function base64urlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(value) {
  const bytes = typeof value === "string" ? enc.encode(value) : value;
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return bufferToHex(digest);
}

function sanitizePublicJwk(jwk) {
  for (const key of ["crv", "kty", "x", "y"]) {
    if (!jwk?.[key]) {
      throw new Error(`missing public JWK field: ${key}`);
    }
  }
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new Error("only EC P-256 keys are supported");
  }
  return {
    crv: String(jwk.crv),
    kty: String(jwk.kty),
    x: String(jwk.x),
    y: String(jwk.y),
  };
}

function sanitizePrivateJwk(jwk) {
  const sanitized = sanitizePublicJwk(jwk);
  if (!jwk?.d) {
    throw new Error("missing private JWK field: d");
  }
  return {
    ...sanitized,
    d: String(jwk.d),
  };
}

function canonicalPublicJwkJson(jwk) {
  const sanitized = sanitizePublicJwk(jwk);
  return JSON.stringify(
    Object.fromEntries(Object.keys(sanitized).sort().map((key) => [key, sanitized[key]])),
  );
}

async function keyIdFromPublicJwk(jwk) {
  return sha256Hex(canonicalPublicJwkJson(jwk));
}

function buildSigningPayload({ challengeId, nonce, method, path, bodySha256, expiresAt }) {
  return JSON.stringify(
    {
      body_sha256: bodySha256,
      challenge_id: challengeId,
      expires_at: expiresAt,
      method: method.toUpperCase(),
      nonce,
      path,
      version: "openclaw-owner-auth-v1",
    },
    Object.keys({
      body_sha256: true,
      challenge_id: true,
      expires_at: true,
      method: true,
      nonce: true,
      path: true,
      version: true,
    }).sort(),
  );
}

function normalizeOwnerStateShape(payload) {
  if (payload?.owner_private_jwk) {
    const ownerPrivateJwk = sanitizePrivateJwk(payload.owner_private_jwk);
    const ownerPublicJwk = sanitizePublicJwk(payload.owner_public_jwk ?? payload.owner_private_jwk);
    return {
      ownerPrivateJwk,
      ownerPublicJwk,
      ownerKeyId: payload.owner_key_id || null,
      stateRoot: payload.state_root ?? null,
      stateGeneration: Number(payload.state_generation ?? 0),
    };
  }

  const ownerPrivateJwk = sanitizePrivateJwk(payload);
  const ownerPublicJwk = sanitizePublicJwk(payload);
  return {
    ownerPrivateJwk,
    ownerPublicJwk,
    ownerKeyId: null,
    stateRoot: null,
    stateGeneration: 0,
  };
}

export async function parseOwnerStateText(text) {
  const payload = JSON.parse(text);
  const normalized = normalizeOwnerStateShape(payload);
  const derivedKeyId = await keyIdFromPublicJwk(normalized.ownerPublicJwk);
  if (normalized.ownerKeyId && normalized.ownerKeyId !== derivedKeyId) {
    throw new Error("owner_key_id does not match the supplied public key");
  }

  return {
    ...normalized,
    ownerKeyId: normalized.ownerKeyId || derivedKeyId,
    persisted: false,
  };
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

function responseError(status, payloadText) {
  const error = new Error(payloadText || `request failed with status ${status}`);
  error.status = status;
  return error;
}

export function describeError(error) {
  if (!error) {
    return "unknown error";
  }
  if (typeof error === "string") {
    return error;
  }
  if (error?.message) {
    return error.message;
  }
  return String(error);
}

export class OwnerStateVault {
  constructor(storageKey = "openclaw.secure-console.owner-state.v1") {
    this.storageKey = storageKey;
  }

  save(ownerState) {
    localStorage.setItem(this.storageKey, JSON.stringify(ownerState));
  }

  restore() {
    const raw = localStorage.getItem(this.storageKey);
    if (!raw) {
      return null;
    }
    try {
      const parsed = JSON.parse(raw);
      return {
        ...parsed,
        persisted: true,
      };
    } catch {
      this.clear();
      return null;
    }
  }

  clear() {
    localStorage.removeItem(this.storageKey);
  }
}

export class OwnerAuthBrowserClient {
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

  async importPrivateKey(privateJwk) {
    return crypto.subtle.importKey(
      "jwk",
      {
        ...privateJwk,
        ext: true,
      },
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      false,
      ["sign"],
    );
  }

  async signPayload(privateJwk, payload) {
    const key = await this.importPrivateKey(privateJwk);
    const signature = await crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: "SHA-256",
      },
      key,
      enc.encode(payload),
    );
    return base64urlEncode(new Uint8Array(signature));
  }

  async requestChallenge(method, path, bodyBytes) {
    const bodySha256 = await sha256Hex(bodyBytes);
    const response = await fetch(`${this.baseUrl}/api/public/challenge`, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        method: method.toUpperCase(),
        path,
        body_sha256: bodySha256,
      }),
    });
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    const challenge = await response.json();
    const expectedPayload = buildSigningPayload({
      challengeId: challenge.challenge_id,
      nonce: challenge.nonce,
      method,
      path,
      bodySha256,
      expiresAt: challenge.expires_at,
    });
    if (challenge.signing_payload !== expectedPayload) {
      throw new Error("server returned an unexpected signing payload");
    }
    return challenge;
  }

  encodeJsonBody(jsonBody) {
    if (jsonBody === null || jsonBody === undefined) {
      return new Uint8Array();
    }
    return enc.encode(JSON.stringify(jsonBody));
  }

  async sendSignedRequest(ownerState, method, path, { jsonBody = null, extraHeaders = {} } = {}) {
    const bodyBytes = this.encodeJsonBody(jsonBody);
    const challenge = await this.requestChallenge(method, path, bodyBytes);
    const signature = await this.signPayload(ownerState.ownerPrivateJwk, challenge.signing_payload);
    const headers = new Headers(extraHeaders);
    headers.set("x-auth-challenge-id", challenge.challenge_id);
    headers.set("x-auth-key-id", ownerState.ownerKeyId);
    headers.set("x-auth-signature", signature);
    if (bodyBytes.byteLength > 0) {
      headers.set("content-type", "application/json");
    }
    return fetch(`${this.baseUrl}${path}`, {
      method: method.toUpperCase(),
      credentials: "same-origin",
      headers,
      body: bodyBytes.byteLength > 0 ? bodyBytes : undefined,
    });
  }

  async login(ownerState) {
    const response = await this.sendSignedRequest(ownerState, "POST", "/api/private/session/login");
    if (!response.ok) {
      throw responseError(response.status, await response.text());
    }
    return response.json();
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

  async sessionFetch(method, path, { jsonBody = null, extraHeaders = {} } = {}) {
    const headers = new Headers(extraHeaders);
    let body;
    if (jsonBody !== null && jsonBody !== undefined) {
      headers.set("content-type", "application/json");
      body = JSON.stringify(jsonBody);
    }
    return fetch(`${this.baseUrl}${path}`, {
      method: method.toUpperCase(),
      credentials: "same-origin",
      headers,
      body,
    });
  }

  async describeResponse(response) {
    const text = await response.text();
    let parsedBody = text;
    const contentType = response.headers.get("content-type") || "";
    if (text && contentType.includes("application/json")) {
      try {
        parsedBody = JSON.parse(text);
      } catch {
        parsedBody = text;
      }
    }

    return {
      status: response.status,
      ok: response.ok,
      headers: Object.fromEntries(response.headers.entries()),
      body: parsedBody,
    };
  }
}
