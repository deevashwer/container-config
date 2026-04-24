FROM ghcr.io/openclaw/openclaw:2026.4.15-slim@sha256:734b55459a9d2eddd58a493577e1ff867a2680f13758349529bec91a0d2c0ea3

ENV OPENCLAW_BOOTSTRAP_HOST=127.0.0.1
ENV OPENCLAW_BOOTSTRAP_PORT=18788
ENV OPENCLAW_UPSTREAM_PORT=18789
ENV OPENCLAW_WORKSPACE_PATH=/openclaw
ENV OPENCLAW_DISABLE_BONJOUR=1

WORKDIR /opt/openclaw-bootstrap

COPY bootstrap-server.js /opt/openclaw-bootstrap/bootstrap-server.js

HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.OPENCLAW_BOOTSTRAP_PORT || '18788') + '/healthz').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "/opt/openclaw-bootstrap/bootstrap-server.js"]
