#!/usr/bin/env bash
# Master Lab Lifecycle Manager
# Automates starting, stopping, and verifying Docker lab enclaves for the curriculum.
set -e

ACTION="${1:-status}"

case "$ACTION" in
    start-all)
        echo "[*] Starting all Docker security enclaves..."
        docker compose -f docker-compose.level1.yml up -d 2>/dev/null || true
        docker compose -f docker-compose.level2.yml up -d 2>/dev/null || true
        docker compose -f docker-compose.level3.yml up -d 2>/dev/null || true
        docker compose -f docker-compose.level5.yml up -d 2>/dev/null || true
        echo "[+] Docker enclaves started."
        ;;
    stop-all)
        echo "[*] Stopping all Docker security enclaves..."
        docker compose -f docker-compose.level1.yml down 2>/dev/null || true
        docker compose -f docker-compose.level2.yml down 2>/dev/null || true
        docker compose -f docker-compose.level3.yml down 2>/dev/null || true
        docker compose -f docker-compose.level5.yml down 2>/dev/null || true
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
