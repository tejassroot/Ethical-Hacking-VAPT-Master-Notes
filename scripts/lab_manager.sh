#!/usr/bin/env bash
# Master Lab Lifecycle Manager
# Automates starting, stopping, and verifying Docker lab enclaves for the curriculum.
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DOCKER_DIR="$REPO_ROOT/docker"

ACTION="${1:-status}"
LEVEL="${2:-all}"

compose_files=(
    "$DOCKER_DIR/docker-compose.level1.yml"
    "$DOCKER_DIR/docker-compose.level2.yml"
    "$DOCKER_DIR/docker-compose.level3.yml"
    "$DOCKER_DIR/docker-compose.level5.yml"
)

case "$ACTION" in
    start-all)
        echo "[*] Starting all Docker security enclaves..."
        for cf in "${compose_files[@]}"; do
            if [ -f "$cf" ]; then
                echo "[+] Launching enclave: $(basename "$cf")"
                docker compose -f "$cf" up -d 2>/dev/null || true
            fi
        done
        echo "[+] Docker enclaves started."
        ;;
    stop-all)
        echo "[*] Stopping all Docker security enclaves..."
        for cf in "${compose_files[@]}"; do
            if [ -f "$cf" ]; then
                echo "[-] Tearing down enclave: $(basename "$cf")"
                docker compose -f "$cf" down 2>/dev/null || true
            fi
        done
        echo "[+] All Docker enclaves stopped."
        ;;
    status)
        echo "[*] Current Active Lab Containers:"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "Docker daemon not running or no active containers."
        ;;
    *)
        echo "Usage: $0 {start-all|stop-all|status}"
        exit 1
        ;;
esac
