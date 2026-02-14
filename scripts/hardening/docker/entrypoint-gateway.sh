#!/bin/sh
# Entrypoint script for ClawdBot Gateway
set -e

# Print startup message
echo "Starting ClawdBot Gateway..."
echo "Environment: ${ENVIRONMENT:-production}"
echo "Log Level: ${LOG_LEVEL:-INFO}"

# Wait for dependencies
echo "Waiting for dependencies..."
if [ -n "$POSTGRES_HOST" ]; then
    until nc -z "$POSTGRES_HOST" "${POSTGRES_PORT:-5432}"; do
        echo "Waiting for PostgreSQL..."
        sleep 2
    done
    echo "PostgreSQL is ready"
fi

if [ -n "$REDIS_HOST" ]; then
    until nc -z "$REDIS_HOST" "${REDIS_PORT:-6379}"; do
        echo "Waiting for Redis..."
        sleep 2
    done
    echo "Redis is ready"
fi

# Run database migrations if needed
if [ "${RUN_MIGRATIONS:-false}" = "true" ]; then
    echo "Running database migrations..."
    python -m clawdbot.db migrate
fi

# Start the gateway
echo "Starting gateway on port ${GATEWAY_PORT:-8443}..."
exec python -m clawdbot.gateway \
    --config /app/config/gateway.yml \
    --host "${GATEWAY_HOST:-0.0.0.0}" \
    --port "${GATEWAY_PORT:-8443}"
