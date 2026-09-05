# ==============================================================================
# Ethical Hacking & VAPT Master Curriculum — Lab Suite Automation Makefile
# Standards: NIST SP 800-115 | OWASP Top 10 | PTES | MITRE ATT&CK
# Author: Tejas's Ethical Hacking & VAPT Curriculum
# ==============================================================================

.PHONY: all help setup test list run interactive docker-up docker-down docker-status clean

PYTHON ?= python3
SHELL  := /bin/bash

# Default Target
all: help

## Display this help screen with command descriptions
help:
	@echo ""
	@echo -e "\033[1;36m================================================================================"
	@echo -e "      ETHICAL HACKING & VAPT MASTER LAB SUITE — MAKE COMMANDS"
	@echo -e "================================================================================\033[0m"
	@echo -e "\033[2mStandards: NIST SP 800-115 | OWASP ASVS/Top 10 | PTES | MITRE ATT&CK\033[0m"
	@echo ""
	@echo -e "\033[1mCore Lifecycle Targets:\033[0m"
	@echo -e "  \033[1;32mmake setup\033[0m            Audit host prerequisites and ensure execute permissions"
	@echo -e "  \033[1;32mmake list\033[0m             List all 34 curriculum modules and lab script paths"
	@echo -e "  \033[1;32mmake test\033[0m             Run full regression test suite across all 34 lab modules"
	@echo -e "  \033[1;32mmake run MODULE=<N>\033[0m   Execute a specific lab by module number (e.g., make run MODULE=30)"
	@echo -e "  \033[1;32mmake interactive\033[0m      Launch interactive terminal lab selection menu"
	@echo ""
	@echo -e "\033[1mDocker Security Enclaves (Optional Containers):\033[0m"
	@echo -e "  \033[1;33mmake docker-up\033[0m        Launch isolated Docker security testing enclaves"
	@echo -e "  \033[1;33mmake docker-down\033[0m      Stop and tear down active Docker security enclaves"
	@echo -e "  \033[1;33mmake docker-status\033[0m    Inspect status of running lab containers"
	@echo ""
	@echo -e "\033[1mMaintenance & Hygiene:\033[0m"
	@echo -e "  \033[1;34mmake clean\033[0m            Remove Python bytecode caches and temporary artifacts"
	@echo -e "  \033[1;34mmake help\033[0m             Display this help manual"
	@echo ""
	@echo -e "\033[1;35mQuickstart Example:\033[0m"
	@echo -e "  git clone https://github.com/tejassroot/Ethical-Hacking-VAPT-Master-Notes.git"
	@echo -e "  cd Ethical-Hacking-VAPT-Master-Notes"
	@echo -e "  make setup"
	@echo -e "  make run MODULE=30"
	@echo ""

## Audit host prerequisites and permissions
setup:
	@chmod +x scripts/*.py scripts/*.sh labs/*/*.py labs/*/*.sh 2>/dev/null || true
	@$(PYTHON) scripts/lab_runner.py --check-env

## List all 34 curriculum modules and lab script paths
list:
	@$(PYTHON) scripts/lab_runner.py --list

## Run full regression test suite across all 34 lab modules
test:
	@$(PYTHON) scripts/lab_runner.py --test-all

## Execute a specific lab by module number (Usage: make run MODULE=30)
run:
	@if [ -z "$(MODULE)" ]; then \
		echo -e "\033[1;31m[!] Error: MODULE parameter is missing.\033[0m"; \
		echo -e "\033[1;33mUsage:\033[0m make run MODULE=<number>   (e.g., make run MODULE=30)"; \
		echo -e "Run '\033[1mmake list\033[0m' to inspect available module numbers 01 to 34."; \
		exit 1; \
	fi
	@$(PYTHON) scripts/lab_runner.py --run $(MODULE)

## Launch interactive terminal lab menu
interactive:
	@$(PYTHON) scripts/lab_runner.py --interactive

## Launch isolated Docker security testing enclaves
docker-up:
	@bash scripts/lab_manager.sh start-all

## Stop and tear down active Docker security enclaves
docker-down:
	@bash scripts/lab_manager.sh stop-all

## Inspect status of running lab containers
docker-status:
	@bash scripts/lab_manager.sh status

## Remove Python bytecode caches and temporary artifacts
clean:
	@echo "[*] Cleaning Python bytecode caches and temporary artifacts..."
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type f -name "*.pyd" -delete 2>/dev/null || true
	@echo "[+] Clean complete."
