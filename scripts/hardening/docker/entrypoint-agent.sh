#!/bin/sh
# Entrypoint script for ClawdBot Agent
set -e

# Print startup message
echo "Starting ClawdBot Agent..."
echo "Environment: ${ENVIRONMENT:-production}"
echo "Gateway URL: ${GATEWAY_URL}"

# Wait for gateway
if [ -n "$GATEWAY_URL" ]; then
    echo "Waiting for gateway..."
    until curl -sf "${GATEWAY_URL}/health" > /dev/null 2>&1; do
        echo "Gateway not ready, retrying in 5s..."
        sleep 5
    done
    echo "Gateway is ready"
fi

# Start the agent
echo "Starting agent worker..."
exec python -m clawdbot.agent \
    --config /app/config/agent.yml \
    --gateway-url "${GATEWAY_URL}" \
    --max-tasks "${MAX_CONCURRENT_TASKS:-5}"
