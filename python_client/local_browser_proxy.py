from __future__ import annotations

import html
import json
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

if TYPE_CHECKING:
    try:
        from python_client.owner_auth_chat import BaseTransport, GatewayPublicClient
    except ModuleNotFoundError:  # pragma: no cover - only used when running as a plain script
        from owner_auth_chat import BaseTransport, GatewayPublicClient


@dataclass(slots=True)
class RemoteGatewayStatus:
    transport: str
    unlock_url: str
    workspace_path: str
    remote_base_url: str
    public_config: dict[str, object]
    verification_document: object | None
    expected_tls_public_key: str | None
    expected_hpke_public_key: str | None


class VerifiedLaunchSession:
    """Verifies the remote target locally, then launches the real remote browser flow."""

    def __init__(self, *, transport: BaseTransport, gateway_client: GatewayPublicClient) -> None:
        self.transport = transport
        self.gateway_client = gateway_client
        self._lock = threading.Lock()
        self.public_config: dict[str, object] = {}
        self.workspace_path = "/openclaw/"
        self.remote_base_url = getattr(transport, "base_url", "").rstrip("/")
        self.unlock_url = f"{self.remote_base_url}/" if self.remote_base_url else "/"
        self._bootstrapped = False

    def bootstrap(self) -> RemoteGatewayStatus:
        with self._lock:
            if self._bootstrapped:
                return self.status()
            self.public_config = self.gateway_client.load_public_config()
            self.workspace_path = str(self.public_config.get("openclaw_workspace_path") or "/openclaw/")
            self.unlock_url = self.gateway_client.unlock_url()
            self._bootstrapped = True
            return self.status()

    def status(self) -> RemoteGatewayStatus:
        verification_document = self.transport.get_verification_document()
        expected_tls_public_key = verification_field(verification_document, "tls_public_key")
        expected_hpke_public_key = verification_field(verification_document, "hpke_public_key")
        return RemoteGatewayStatus(
            transport=self.transport.describe(),
            unlock_url=self.unlock_url,
            workspace_path=self.workspace_path,
            remote_base_url=self.remote_base_url,
            public_config=self.public_config,
            verification_document=verification_document,
            expected_tls_public_key=expected_tls_public_key,
            expected_hpke_public_key=expected_hpke_public_key,
        )

    def close(self) -> None:
        self.transport.close()


def create_browser_gateway_app(session: VerifiedLaunchSession) -> FastAPI:
    if not session.remote_base_url:
        raise ValueError("transport does not expose a remote base URL")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            app.state.remote_status = session.bootstrap()
            yield
        finally:
            session.close()

    app = FastAPI(title="OpenClaw Local Verification Center", lifespan=lifespan)
    app.state.remote_session = session

    def jsonable(value: object) -> object:
        if is_dataclass(value):
            return {key: jsonable(item) for key, item in asdict(value).items()}
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, dict):
            return {str(key): jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [jsonable(item) for item in value]
        return value

    def launch_url_for_status(status_payload: RemoteGatewayStatus) -> str:
        if not status_payload.unlock_url:
            return "/"
        parts = urlsplit(status_payload.unlock_url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query["local_verifier_gap"] = "1"
        if status_payload.expected_tls_public_key:
            query["local_verified_tls_public_key"] = status_payload.expected_tls_public_key
        if status_payload.expected_hpke_public_key:
            query["local_verified_hpke_public_key"] = status_payload.expected_hpke_public_key
        return urlunsplit(parts._replace(query=urlencode(query)))

    def render_dashboard(status_payload: RemoteGatewayStatus) -> str:
        verification = jsonable(status_payload.verification_document) if status_payload.verification_document is not None else None
        security_verified = bool(getattr(status_payload.verification_document, "security_verified", False))
        if isinstance(verification, dict):
            security_verified = bool(verification.get("security_verified", security_verified))

        remote_host = status_payload.remote_base_url or "remote enclave"
        workspace_path = status_payload.workspace_path or "/openclaw/"
        unlock_url = status_payload.unlock_url or "/"
        launch_url = launch_url_for_status(status_payload)
        pretty_verification = json.dumps(verification or {"security_verified": False}, indent=2)
        verification_state = "Verified" if security_verified else "Unverified"
        verification_color = "#2d6a4f" if security_verified else "#9a3412"
        verification_bg = "#e8f5e9" if security_verified else "#fff7ed"
        verification_copy = (
            "Python verified the remote enclave attestation and pinned the attested TLS key locally. "
            "Passkey approval and secret storage still happen on the remote enclave origin."
            if security_verified
            else "This local verification center is running, but the upstream attestation is not marked verified."
        )
        initialization_available = bool(status_payload.public_config.get("initialization_available"))
        passkey_count = int(status_payload.public_config.get("passkey_count") or 0)
        passkey_state = "Unclaimed" if initialization_available else "Claimed"
        primary_label = "Open Remote Initialization Page" if initialization_available else "Open Remote Unlock Page"

        escaped_remote_host = html.escape(remote_host)
        escaped_workspace_path = html.escape(workspace_path)
        escaped_unlock_url = html.escape(unlock_url)
        escaped_launch_url = html.escape(launch_url)
        escaped_transport = html.escape(status_payload.transport)
        escaped_verification_copy = html.escape(verification_copy)
        escaped_pretty_verification = html.escape(pretty_verification)
        escaped_passkey_state = html.escape(passkey_state)
        escaped_primary_label = html.escape(primary_label)
        escaped_expected_tls_public_key = html.escape(status_payload.expected_tls_public_key or "Unavailable")
        escaped_expected_hpke_public_key = html.escape(status_payload.expected_hpke_public_key or "Unavailable")

        return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>OpenClaw Verified Launch Center</title>
    <style>
      :root {{
        color-scheme: light;
        --bg: #f5f1e8;
        --card: #fffdf8;
        --ink: #1f2933;
        --muted: #52606d;
        --border: #d9cbb5;
        --accent: #0f766e;
      }}
      * {{ box-sizing: border-box; }}
      body {{
        margin: 0;
        font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", serif;
        background:
          radial-gradient(circle at top left, rgba(15, 118, 110, 0.12), transparent 32rem),
          linear-gradient(180deg, #f7f2e9 0%, var(--bg) 100%);
        color: var(--ink);
      }}
      main {{
        max-width: 980px;
        margin: 0 auto;
        padding: 48px 20px 64px;
      }}
      .hero {{
        display: grid;
        gap: 18px;
        margin-bottom: 28px;
      }}
      .eyebrow {{
        font: 600 0.84rem/1.2 ui-monospace, "SFMono-Regular", "SF Mono", Consolas, monospace;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--accent);
      }}
      h1 {{
        margin: 0;
        font-size: clamp(2.2rem, 6vw, 4rem);
        line-height: 0.96;
      }}
      .lede {{
        max-width: 52rem;
        font-size: 1.06rem;
        line-height: 1.6;
        color: var(--muted);
      }}
      .grid {{
        display: grid;
        gap: 16px;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        margin-bottom: 24px;
      }}
      .card {{
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 18px;
        box-shadow: 0 10px 24px rgba(31, 41, 51, 0.05);
      }}
      .status-card {{
        background: {verification_bg};
        border-color: rgba(31, 41, 51, 0.08);
      }}
      .label {{
        font: 600 0.78rem/1.2 ui-monospace, "SFMono-Regular", "SF Mono", Consolas, monospace;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
        margin-bottom: 8px;
      }}
      .value {{
        font-size: 1.15rem;
        line-height: 1.35;
        word-break: break-word;
      }}
      .pill {{
        display: inline-flex;
        align-items: center;
        gap: 0.5rem;
        padding: 0.42rem 0.75rem;
        border-radius: 999px;
        font: 700 0.85rem/1 ui-monospace, "SFMono-Regular", "SF Mono", Consolas, monospace;
        background: rgba(255,255,255,0.72);
        color: {verification_color};
        border: 1px solid rgba(31,41,51,0.08);
      }}
      .actions {{
        display: flex;
        flex-wrap: wrap;
        gap: 12px;
        margin: 24px 0 8px;
      }}
      .button {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 48px;
        padding: 0 20px;
        border-radius: 999px;
        text-decoration: none;
        font-weight: 700;
        border: 1px solid transparent;
      }}
      .button-primary {{
        background: var(--accent);
        color: #f8fffd;
      }}
      .button-secondary {{
        background: rgba(255,255,255,0.72);
        color: var(--ink);
        border-color: var(--border);
      }}
      pre {{
        margin: 0;
        padding: 18px;
        overflow-x: auto;
        border-radius: 18px;
        border: 1px solid #1f29331a;
        background: #102a43;
        color: #d9e2ec;
        font: 500 0.85rem/1.55 ui-monospace, "SFMono-Regular", "SF Mono", Consolas, monospace;
      }}
      .footer-note {{
        margin-top: 14px;
        color: var(--muted);
        line-height: 1.6;
      }}
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <div class="eyebrow">Verified Launch Center</div>
        <h1>Verify locally, then continue on the real enclave origin.</h1>
        <div class="lede">
          <p>{escaped_verification_copy}</p>
          <p>
            This local page is a verifier and launcher. It is not a proxy in the browser data path.
            When you continue, your browser moves to <code>{escaped_remote_host}</code> so WebAuthn/passkeys
            and the browser-local secret vault stay bound to the real enclave origin.
          </p>
        </div>
      </section>

      <section class="grid">
        <article class="card status-card">
          <div class="label">Verification</div>
          <div class="pill">{verification_state}</div>
          <p class="footer-note">Use this local result to decide whether to continue to the remote unlock page.</p>
        </article>
        <article class="card">
          <div class="label">Remote Enclave</div>
          <div class="value"><code>{escaped_remote_host}</code></div>
        </article>
        <article class="card">
          <div class="label">Passkey State</div>
          <div class="value">{escaped_passkey_state} ({passkey_count} stored)</div>
        </article>
        <article class="card">
          <div class="label">Workspace Path</div>
          <div class="value"><code>{escaped_workspace_path}</code></div>
        </article>
        <article class="card">
          <div class="label">Transport</div>
          <div class="value">{escaped_transport}</div>
        </article>
        <article class="card">
          <div class="label">Remote Unlock URL</div>
          <div class="value"><code>{escaped_unlock_url}</code></div>
        </article>
        <article class="card">
          <div class="label">Expected TLS Key</div>
          <div class="value"><code>{escaped_expected_tls_public_key}</code></div>
        </article>
        <article class="card">
          <div class="label">Expected HPKE Key</div>
          <div class="value"><code>{escaped_expected_hpke_public_key}</code></div>
        </article>
      </section>

      <div class="actions">
        <a class="button button-primary" href="/launch">{escaped_primary_label}</a>
        <a class="button button-secondary" href="/api/local/status">Raw Verification JSON</a>
      </div>

      <p class="footer-note">
        The launch link carries the locally verified key fingerprints into the remote page as a continuity hint.
        The browser still does not cryptographically confirm that hint on its own yet.
      </p>

      <section class="card">
        <div class="label">Verification Document</div>
        <pre>{escaped_pretty_verification}</pre>
      </section>
    </main>
  </body>
</html>"""

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/local/status")
    async def local_status() -> JSONResponse:
        status_payload = session.status()
        return JSONResponse(
            {
                "transport": status_payload.transport,
                "unlock_url": status_payload.unlock_url,
                "workspace_path": status_payload.workspace_path,
                "remote_base_url": status_payload.remote_base_url,
                "launch_url": launch_url_for_status(status_payload),
                "expected_tls_public_key": status_payload.expected_tls_public_key,
                "expected_hpke_public_key": status_payload.expected_hpke_public_key,
                "public_config": status_payload.public_config,
                "verification_document": jsonable(status_payload.verification_document),
            }
        )

    @app.get("/", include_in_schema=False)
    async def landing_page() -> HTMLResponse:
        return HTMLResponse(render_dashboard(session.status()))

    @app.get("/launch", include_in_schema=False)
    async def launch_remote() -> RedirectResponse:
        return RedirectResponse(url=launch_url_for_status(session.status()), status_code=307)

    return app


def verification_field(document: object | None, field_name: str) -> str | None:
    if document is None:
        return None
    if isinstance(document, dict):
        value = document.get(field_name)
        return str(value) if value else None
    value = getattr(document, field_name, None)
    return str(value) if value else None
