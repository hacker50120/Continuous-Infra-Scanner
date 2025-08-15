#!/bin/bash

# InfraScanner Pro - Spin up and get endpoint

set -e

# Check Docker engine
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Start Docker and rerun this script."
    exit 1
fi

# Move to InfraScanner docker folder
SCRIPT_DIR=$(dirname -- "$0")
DOCKER_DIR="$SCRIPT_DIR/IaC/docker"

cd "$DOCKER_DIR"

# Start the stack

echo "🚀 Starting InfraScanner Pro containers..."
docker-compose up -d --build

echo "⏳ Waiting for services to be healthy..."

# Wait for the main app container to be healthy (max 60s)
for i in {1..12}; do
    STATUS=$(docker inspect -f '{{.State.Health.Status}}' infrascanner-app 2>/dev/null || echo "none")
    if [ "$STATUS" == "healthy" ]; then
        echo "✅ InfraScanner app container is running and healthy."
        break
    else
        echo "Waiting for container health: $STATUS"
        sleep 5
    fi
    if [ $i -eq 12 ]; then
        echo "⚠️ InfraScanner app container health check timed out."
        docker logs infrascanner-app --tail 20
        exit 1
    fi
 done

# Output the endpoint

PORT=8181

echo "🌐 InfraScanner Pro is running!"
echo "Access the web UI at: http://localhost:$PORT"

cat << EOF
Use Ctrl+C to stop the stack later with:
docker-compose down
EOF
