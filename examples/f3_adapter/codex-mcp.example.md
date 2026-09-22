# Codex MCP registration template

Replace both absolute paths. `TAS_ADAPTER_CONFIG` points to non-secret JSON; never add the Credential to this command or to Codex configuration.

The optional `tls_ca_file` in `adapter.json` is only for an Owner-managed private CA bundle. It does not disable certificate-chain or hostname verification.

Windows PowerShell:

```powershell
codex mcp add team-agent-system `
  --env TAS_ADAPTER_CONFIG="C:\absolute\path\adapter.json" `
  -- "C:\absolute\path\.venv\Scripts\tas-adapter-mcp.exe"
```

macOS/Linux shell (planned, not yet smoke-tested):

```bash
codex mcp add team-agent-system \
  --env TAS_ADAPTER_CONFIG=/absolute/path/adapter.json \
  -- /absolute/path/.venv/bin/tas-adapter-mcp
```

Install the Credential interactively before starting Codex:

```text
tas-adapter credential-set
tas-adapter smoke
```
