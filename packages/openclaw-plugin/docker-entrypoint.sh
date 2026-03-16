#!/bin/sh
set -e

CONFIG_DIR="${HOME}/.openclaw"
CONFIG_FILE="${CONFIG_DIR}/openclaw.json"

# Create required directories (avoids CRITICAL doctor warnings)
mkdir -p "${CONFIG_DIR}/agents/main/sessions" "${CONFIG_DIR}/credentials" "${CONFIG_DIR}/workspace" 2>/dev/null || true
chmod 700 "${CONFIG_DIR}" 2>/dev/null || true

# Generate OpenClaw config from environment variables
# - LLM provider routes through executor's proxy
# - Telegram bot token is a placeholder (egress proxy substitutes real value)
# - Plugin loaded from /app/plugin/
cat > "${CONFIG_FILE}" << EOCFG
{
  "models": {
    "mode": "merge",
    "providers": {
      "sentinel-openai": {
        "baseUrl": "${SENTINEL_EXECUTOR_URL:-http://executor:3141}/proxy/llm/openai/v1",
        "apiKey": "${SENTINEL_AUTH_TOKEN:-}",
        "api": "openai-completions",
        "models": [
          {
            "id": "gpt-5.4",
            "name": "GPT-5.4",
            "contextWindow": 1047576,
            "maxTokens": 32768
          }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "model": "sentinel-openai/gpt-5.4",
      "workspace": "/home/node/.openclaw/workspace"
    }
  },
  "channels": {
    "telegram": {
      "botToken": "SENTINEL_PLACEHOLDER_telegram_bot__key",
      "enabled": true,
      "dmPolicy": "pairing",
      "groupPolicy": "allowlist",
      "streaming": "partial"
    }
  },
  "plugins": {
    "entries": {
      "sentinel": {
        "enabled": true,
        "config": {
          "executorUrl": "${SENTINEL_EXECUTOR_URL:-http://executor:3141}",
          "authToken": "${SENTINEL_AUTH_TOKEN:-}",
          "failMode": "${SENTINEL_FAIL_MODE:-closed}",
          "tier": "Normal"
        }
      }
    },
    "load": {
      "paths": ["/app/plugin"]
    }
  },
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "lan"
  }
}
EOCFG

echo "[openclaw-gateway] Config written to ${CONFIG_FILE}"
echo "[openclaw-gateway] Executor: ${SENTINEL_EXECUTOR_URL:-http://executor:3141}"
echo "[openclaw-gateway] Plugin: /app/plugin"

# Start OpenClaw gateway (no self-respawn in container)
echo "[openclaw-gateway] Starting OpenClaw gateway..."
export OPENCLAW_NO_RESPAWN=1
export NODE_OPTIONS="--max-old-space-size=1536"
chmod 600 "${CONFIG_FILE}" 2>/dev/null || true
exec openclaw gateway run --port 18789 --bind lan --allow-unconfigured
