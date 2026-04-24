"use strict";

const fs = require("node:fs");
const http = require("node:http");
const { spawn } = require("node:child_process");

const bootstrapHost = process.env.OPENCLAW_BOOTSTRAP_HOST || "127.0.0.1";
const bootstrapPort = Number(process.env.OPENCLAW_BOOTSTRAP_PORT || "18788");
const upstreamPort = Number(process.env.OPENCLAW_UPSTREAM_PORT || "18789");
const workspacePath = process.env.OPENCLAW_WORKSPACE_PATH || "/openclaw";
const upstreamReadyTimeoutMs = Number(process.env.OPENCLAW_BOOTSTRAP_WAIT_MS || "90000");
const defaultPrimaryModel = process.env.OPENCLAW_DEFAULT_MODEL || "anthropic/claude-sonnet-4-6";
const defaultFallbackModels = (process.env.OPENCLAW_FALLBACK_MODELS || "anthropic/claude-opus-4-6")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const openClawHome = "/home/node/.openclaw";
const sessionsPath = `${openClawHome}/agents/main/sessions/sessions.json`;
const openClawConfigPath = `${openClawHome}/openclaw.json`;

const state = {
  status: "waiting",
  appliedEnv: null,
  launchPromise: null,
  child: null,
  error: null,
};

function json(response, statusCode, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function canonicalEnv(env) {
  const normalized = {};
  for (const key of Object.keys(env).sort()) {
    normalized[key] = String(env[key]);
  }
  return normalized;
}

function buildOpenClawConfig() {
  const allowedModels = {
    [defaultPrimaryModel]: { alias: "primary" },
  };
  for (const fallbackModel of defaultFallbackModels) {
    if (!(fallbackModel in allowedModels)) {
      allowedModels[fallbackModel] = { alias: fallbackModel.split("/").pop() || "fallback" };
    }
  }

  return {
    gateway: {
      mode: "local",
      bind: "loopback",
      trustedProxies: ["127.0.0.1", "::1"],
      controlUi: {
        basePath: workspacePath,
        embedSandbox: "strict",
        allowedOrigins: ["*"],
        dangerouslyDisableDeviceAuth: true,
      },
      auth: { mode: "none" },
    },
    agents: {
      defaults: {
        model: {
          primary: defaultPrimaryModel,
          fallbacks: defaultFallbackModels,
        },
        // Restrict the default session to Anthropic so stale Bedrock/OpenAI
        // overrides get rejected and rewritten during startup.
        models: allowedModels,
      },
    },
  };
}

function writeOpenClawConfig() {
  fs.mkdirSync(openClawHome, { recursive: true });
  fs.writeFileSync(
    openClawConfigPath,
    JSON.stringify(buildOpenClawConfig()),
  );
}

function parseModelRef(ref) {
  const trimmed = String(ref || "").trim();
  const slashIndex = trimmed.indexOf("/");
  if (slashIndex <= 0 || slashIndex === trimmed.length - 1) {
    throw new Error(`invalid model ref: ${trimmed || "(empty)"}`);
  }
  return {
    provider: trimmed.slice(0, slashIndex),
    model: trimmed.slice(slashIndex + 1),
  };
}

function normalizeSessionOverrides() {
  if (!fs.existsSync(sessionsPath)) {
    return;
  }

  const { provider, model } = parseModelRef(defaultPrimaryModel);
  const raw = fs.readFileSync(sessionsPath, "utf-8");
  if (!raw.trim()) {
    return;
  }

  const sessions = JSON.parse(raw);
  if (!sessions || typeof sessions !== "object" || Array.isArray(sessions)) {
    return;
  }

  let changed = false;
  for (const entry of Object.values(sessions)) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      continue;
    }
    if (
      entry.providerOverride !== provider ||
      entry.modelOverride !== model ||
      entry.modelOverrideSource !== "bootstrap" ||
      entry.authProfileOverride
    ) {
      entry.providerOverride = provider;
      entry.modelOverride = model;
      entry.modelOverrideSource = "bootstrap";
      delete entry.authProfileOverride;
      entry.updatedAt = Date.now();
      changed = true;
    }
  }

  if (changed) {
    fs.writeFileSync(sessionsPath, JSON.stringify(sessions, null, 2));
  }
}

function waitForUpstreamHealth() {
  const deadline = Date.now() + upstreamReadyTimeoutMs;
  const targetUrl = `http://127.0.0.1:${upstreamPort}/healthz`;
  return new Promise((resolve, reject) => {
    const poll = () => {
      const request = http.get(targetUrl, (response) => {
        response.resume();
        if (response.statusCode && response.statusCode >= 200 && response.statusCode < 300) {
          resolve();
          return;
        }
        if (Date.now() >= deadline) {
          reject(new Error(`upstream healthcheck returned ${response.statusCode || "unknown"}`));
          return;
        }
        setTimeout(poll, 500);
      });
      request.on("error", () => {
        if (Date.now() >= deadline) {
          reject(new Error(`upstream healthcheck timed out after ${upstreamReadyTimeoutMs}ms`));
          return;
        }
        setTimeout(poll, 500);
      });
    };
    poll();
  });
}

async function launchOpenClaw(env) {
  state.status = "starting";
  state.error = null;
  writeOpenClawConfig();
  normalizeSessionOverrides();
  const childEnv = {
    ...process.env,
    ...env,
    OPENCLAW_DISABLE_BONJOUR: process.env.OPENCLAW_DISABLE_BONJOUR || "1",
  };

  const child = spawn("docker-entrypoint.sh", ["node", "/app/openclaw.mjs", "gateway", "--allow-unconfigured"], {
    cwd: "/app",
    env: childEnv,
    stdio: "inherit",
  });
  state.child = child;

  child.on("exit", (code, signal) => {
    const details = `openclaw exited code=${code === null ? "null" : code} signal=${signal || "none"}`;
    state.error = details;
    state.status = "exited";
    if (!server.listening) {
      return;
    }
    if (process.exitCode === undefined) {
      process.exitCode = code === null ? 1 : code;
    }
  });

  await waitForUpstreamHealth();
  state.status = "ready";
}

function startBootstrappedLaunch(env) {
  const normalizedEnv = canonicalEnv(env);
  if (state.launchPromise) {
    const sameEnv =
      JSON.stringify(normalizedEnv) === JSON.stringify(state.appliedEnv || {});
    if (!sameEnv) {
      throw new Error("bootstrap env already applied with different values");
    }
    return state.launchPromise;
  }

  state.appliedEnv = normalizedEnv;
  state.launchPromise = launchOpenClaw(normalizedEnv);
  return state.launchPromise;
}

function readJsonBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf-8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (error) {
        reject(error);
      }
    });
    request.on("error", reject);
  });
}

function sanitizeBootstrapEnv(payload) {
  const env = payload && typeof payload === "object" ? payload.env : {};
  if (!env || typeof env !== "object" || Array.isArray(env)) {
    throw new Error("env must be an object");
  }

  const allowedKeys = new Set(["ANTHROPIC_API_KEY"]);
  const sanitized = {};
  for (const [key, value] of Object.entries(env)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`unsupported bootstrap env key: ${key}`);
    }
    if (value === null || value === undefined || value === "") {
      continue;
    }
    sanitized[key] = String(value);
  }
  return sanitized;
}

const server = http.createServer(async (request, response) => {
  if (request.method === "GET" && request.url === "/healthz") {
    json(response, 200, {
      status: state.status,
      ready: state.status === "ready",
      configured: state.appliedEnv !== null,
      error: state.error,
    });
    return;
  }

  if (request.method === "POST" && request.url === "/api/bootstrap/config") {
    try {
      const payload = await readJsonBody(request);
      const env = sanitizeBootstrapEnv(payload);
      await startBootstrappedLaunch(env);
      json(response, 200, {
        status: state.status,
        ready: state.status === "ready",
        configured_env_keys: Object.keys(state.appliedEnv || {}),
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      json(response, 409, {
        status: state.status,
        ready: false,
        error: message,
      });
    }
    return;
  }

  json(response, 404, { detail: "not found" });
});

function stopChild(signal) {
  if (state.child && !state.child.killed) {
    state.child.kill(signal);
  }
}

process.on("SIGTERM", () => {
  stopChild("SIGTERM");
  server.close(() => process.exit(0));
});

process.on("SIGINT", () => {
  stopChild("SIGINT");
  server.close(() => process.exit(0));
});

server.listen(bootstrapPort, bootstrapHost, () => {
  console.log(`[openclaw-bootstrap] listening on http://${bootstrapHost}:${bootstrapPort} upstream_port=${upstreamPort}`);
});
