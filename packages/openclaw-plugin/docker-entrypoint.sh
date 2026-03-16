#!/bin/sh
set -e

CONFIG_DIR="${HOME}/.openclaw"
CONFIG_FILE="${CONFIG_DIR}/openclaw.json"

mkdir -p "${CONFIG_DIR}"

# Generate OpenClaw config from environment variables
# - LLM provider routes through executor's proxy
# - Telegram bot token is a placeholder (egress proxy substitutes real value)
# - Plugin loaded from /app/plugin/
cat > "${CONFIG_FILE}" << EOCFG
{
  "models": {
    "providers": {
      "sentinel-openai": {
        "baseUrl": "${SENTINEL_EXECUTOR_URL:-http://executor:3141}/proxy/llm/openai/v1",
        "apiKey": "${SENTINEL_AUTH_TOKEN:-}",
        "api": "openai"
      }
    },
    "default": "sentinel-openai"
  },
  "channels": {
    "telegram": {
      "botToken": "SENTINEL_PLACEHOLDER_telegram_bot__key",
      "enabled": true
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
    "bind": "0.0.0.0"
  }
}
EOCFG

echo "[openclaw-gateway] Config written to ${CONFIG_FILE}"
echo "[openclaw-gateway] Executor: ${SENTINEL_EXECUTOR_URL:-http://executor:3141}"
echo "[openclaw-gateway] Plugin: /app/plugin"

# Start OpenClaw gateway
exec openclaw gateway run --port 18789 --bind lan --allow-unconfigured
