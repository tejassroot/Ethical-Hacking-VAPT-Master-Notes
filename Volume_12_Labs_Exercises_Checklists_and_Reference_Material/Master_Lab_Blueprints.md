# Volume 12: Labs, Exercises, Checklists & Reference Material
# Master Lab Blueprints: Multi-Tier Docker, Virtualized Enclaves & Cloud Emulation Environments

---

## 1. Executive Overview & Lab Engineering Principles

This master laboratory blueprint compendium provides reproducible, production-grade deployment configurations for building safe, isolated, and legally compliant security research enclaves.

Security research, vulnerability reproduction, and detection rule validation must **never** be conducted against unisolated production networks or arbitrary external hosts. The five lab blueprints detailed herein provide standardized environments across the full security spectrum:
* **Level 1 (Foundational)**: Linux Diagnostic & Layer 2/3/4 Network Tooling Enclave.
* **Level 2 (Application & API)**: Multi-Tier Web Application & Microservices Enclave (OWASP Juice Shop, DVWA, crAPI, PostgreSQL).
* **Level 3 (Enterprise DMZ & Defense)**: Dual-Subnet Isolated DMZ with Nginx Reverse Proxy, ModSecurity WAF, and Suricata NIDS.
* **Level 4 (Enterprise Identity & Infrastructure)**: Multi-Node Vagrant Active Directory Domain Enclave with Windows Server 2022 and pfSense.
* **Level 5 (Cloud Security Emulation)**: LocalStack & MinIO AWS Cloud Infrastructure Enclave for IAM and S3 security audits.

### 1.1 Core Isolation & Safety Rules
1. **Loopback Binding (`127.0.0.1`)**: All exposed host ports must be explicitly bound to `127.0.0.1` (e.g., `"127.0.0.1:8080:80"`). Binding to `0.0.0.0` is strictly prohibited to prevent exposing vulnerable lab services to local physical networks.
2. **Internal Isolated Bridges**: Multi-tier containers communicate across user-defined Docker bridge networks with strict IPAM subnets (`172.30.0.0/16`).
3. **Pristine Snapshot Baselines**: In virtual machine environments (VirtualBox/VMware), always maintain an immutable "Clean Baseline" snapshot prior to executing any tests.

---

## 2. Level 1 Lab Blueprint: Local Diagnostics & Network Tooling Enclave

A lightweight, high-performance container equipped with standard network diagnostic utilities (`curl`, `nmap`, `tcpdump`, `dig`, `jq`, `socat`, `scapy`) for protocol experimentation and packet analysis.

### 2.1 Deployment Configuration: `docker-compose.level1.yml`
```yaml
version: '3.8'

networks:
  diag_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.1.0/24

services:
  diag_workstation:
    image: alpine:latest
    container_name: lab_diag_workstation
    hostname: diag-box
    networks:
      diag_net:
        ipv4_address: 172.30.1.10
    cap_add:
      - NET_ADMIN
      - NET_RAW
    command: >
      sh -c "apk update && apk add --no-cache \
             curl wget bind-tools nmap tcpdump jq bash \
             busybox-extras iproute2 net-tools iperf3 socat python3 py3-pip && \
             tail -f /dev/null"
    restart: unless-stopped
```

### 2.2 Execution & Verification Commands
```bash
# 1. Launch container in background
docker compose -f docker-compose.level1.yml up -d

# 2. Attach interactive bash shell
docker exec -it lab_diag_workstation bash

# 3. Verify tool availability
nmap --version
tcpdump --version
curl --version

# 4. Teardown
docker compose -f docker-compose.level1.yml down
```

---

## 3. Level 2 Lab Blueprint: Modern Web & API Testing Enclave

Combines modern Single-Page Applications (OWASP Juice Shop), classic server-side vulnerable applications (Damn Vulnerable Web App - DVWA), and an isolated relational database backend.

```
[ Host Browser / Burp Proxy ]
            │
            ▼ (Access via 127.0.0.1 strictly)
+───────────────────────────────────────────────────────────────────────────────+
| Isolated Docker Network: 172.30.2.0/24                                        |
|                                                                               |
|  [ OWASP Juice Shop ]               [ DVWA Web App ]                          |
|  IP: 172.30.2.10                    IP: 172.30.2.20                           |
|  Port: 127.0.0.1:3000               Port: 127.0.0.1:8080                      |
|  (SPA / Node.js / Express)          (Classic PHP / Apache)                    |
|                                             │                                 |
|                                             ▼                                 |
|                                     [ MySQL / MariaDB Backend ]               |
|                                     IP: 172.30.2.30 (Internal Only)           |
+───────────────────────────────────────────────────────────────────────────────+
```

### 3.1 Deployment Configuration: `docker-compose.level2.yml`
```yaml
version: '3.8'

networks:
  vuln_web_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.2.0/24

services:
  # OWASP Juice Shop: Modern Single Page Application & REST API
  juice_shop:
    image: bkimminich/juice-shop:latest
    container_name: lab_juice_shop
    networks:
      vuln_web_net:
        ipv4_address: 172.30.2.10
    ports:
      - "127.0.0.1:3000:3000"
    environment:
      - NODE_ENV=development
    restart: unless-stopped

  # MariaDB Relational Database Backend
  mariadb_db:
    image: mariadb:10.5
    container_name: lab_mariadb
    networks:
      vuln_web_net:
        ipv4_address: 172.30.2.30
    environment:
      - MYSQL_ROOT_PASSWORD=LabSecRootPassword2026!
      - MYSQL_DATABASE=dvwa_db
      - MYSQL_USER=dvwa_user
      - MYSQL_PASSWORD=LabSecUserPassword2026!
    restart: unless-stopped

  # DVWA (Damn Vulnerable Web App)
  dvwa_app:
    image: vulnerables/web-dvwa:latest
    container_name: lab_dvwa
    networks:
      vuln_web_net:
        ipv4_address: 172.30.2.20
    ports:
      - "127.0.0.1:8080:80"
    depends_on:
      - mariadb_db
    restart: unless-stopped
```

### 3.2 Launch & Health Check
```bash
docker compose -f docker-compose.level2.yml up -d

# Verify services respond cleanly on loopback
curl -I http://127.0.0.1:3000/
curl -I http://127.0.0.1:8080/
```

---

## 4. Level 3 Lab Blueprint: Enterprise DMZ, WAF & Suricata NIDS Enclave

Simulates an enterprise dual-tier network architecture with an edge reverse proxy (Nginx) enforcing rate limits and WAF rules, forwarding to internal microservices while Suricata NIDS monitors traffic on the internal bridge.

```
[ External Ingress ] ---> [ Nginx Reverse Proxy & WAF ] (DMZ: 172.30.3.10)
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
    [ Internal Service A: Web App ]         [ Suricata NIDS Sniffing Sensor ]
        (Internal: 172.30.4.20)                 (Monitors 172.30.4.0/24 Subnet)
```

### 4.1 Deployment Configuration: `docker-compose.level3.yml`
```yaml
version: '3.8'

networks:
  dmz_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.3.0/24
  internal_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.4.0/24

services:
  # Edge Nginx Gateway & Reverse Proxy
  edge_gateway:
    image: nginx:alpine
    container_name: lab_edge_gateway
    networks:
      dmz_net:
        ipv4_address: 172.30.3.10
      internal_net:
        ipv4_address: 172.30.4.10
    ports:
      - "127.0.0.1:8443:443"
      - "127.0.0.1:8000:80"
    volumes:
      - ./nginx_dmz.conf:/etc/nginx/nginx.conf:ro
    restart: unless-stopped

  # Vulnerable Internal Microservice (No Public Ports)
  internal_backend:
    image: python:3.10-slim
    container_name: lab_internal_backend
    networks:
      internal_net:
        ipv4_address: 172.30.4.20
    command: >
      sh -c "python3 -m http.server 8080 --directory /tmp"
    restart: unless-stopped

  # Suricata Network Intrusion Detection Sensor
  suricata_sensor:
    image: jasonish/suricata:latest
    container_name: lab_suricata_sensor
    networks:
      internal_net:
        ipv4_address: 172.30.4.30
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_NICE
    volumes:
      - ./suricata_rules/:/var/lib/suricata/rules:ro
      - ./suricata_logs/:/var/log/suricata
    command: -i eth0 -k none
    restart: unless-stopped
```

---

## 5. Level 4 Lab Blueprint: Enterprise Active Directory & Network Enclave

For practicing Active Directory enumeration, Kerberoasting, AS-REP roasting, DCSync, and domain privilege escalation, a virtualized multi-VM environment managed via Vagrant and VirtualBox is the enterprise standard.

### 5.1 Vagrantfile Architecture (`Vagrantfile`)
```ruby
# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box_check_update = false

  # -------------------------------------------------------------
  # VM 1: Windows Server 2022 Domain Controller (DC01.CORP.LOCAL)
  # -------------------------------------------------------------
  config.vm.define "dc01" do |dc|
    dc.vm.box = "opentable/win-2022-standard-amd64-nocm"
    dc.vm.hostname = "DC01"
    dc.vm.network "private_network", ip: "192.168.56.10"
    
    dc.vm.provider "virtualbox" do |vb|
      vb.name = "Enterprise_Lab_DC01"
      vb.memory = "4096"
      vb.cpus = 2
    end
  end

  # -------------------------------------------------------------
  # VM 2: Windows 10 Enterprise Client Workstation (WKSTN01)
  # -------------------------------------------------------------
  config.vm.define "wkstn01" do |client|
    client.vm.box = "opentable/win-10-enterprise-amd64-nocm"
    client.vm.hostname = "WKSTN01"
    client.vm.network "private_network", ip: "192.168.56.20"
    
    client.vm.provider "virtualbox" do |vb|
      vb.name = "Enterprise_Lab_WKSTN01"
      vb.memory = "3072"
      vb.cpus = 2
    end
  end

  # -------------------------------------------------------------
  # VM 3: Linux Security Assessment Workstation (Kali Linux)
  # -------------------------------------------------------------
  config.vm.define "kali" do |kali|
    kali.vm.box = "kalilinux/rolling"
    kali.vm.hostname = "kali-auditor"
    kali.vm.network "private_network", ip: "192.168.56.100"
    
    kali.vm.provider "virtualbox" do |vb|
      vb.name = "Enterprise_Lab_Kali"
      vb.memory = "4096"
      vb.cpus = 2
    end
  end
end
```

### 5.2 Launch & Provisioning Commands
```bash
# 1. Start all VMs in isolated host-only network (192.168.56.0/24)
vagrant up

# 2. SSH into Kali assessment workstation
vagrant ssh kali

# 3. Verify network reachability to DC01 without internet routing
ping -c 3 192.168.56.10
```

---

## 6. Level 5 Lab Blueprint: Cloud Emulation Enclave (LocalStack & MinIO)

Auditing cloud-native security, IAM policies, and S3 bucket permissions requires an isolated local AWS cloud simulation without incurring cloud vendor billing or risking public exposure.

### 6.1 Deployment Configuration: `docker-compose.level5.yml`
```yaml
version: '3.8'

networks:
  cloud_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.30.5.0/24

services:
  # LocalStack: Fully functional local AWS Cloud stack (S3, IAM, Lambda, STS)
  localstack:
    image: localstack/localstack:latest
    container_name: lab_localstack
    networks:
      cloud_net:
        ipv4_address: 172.30.5.10
    ports:
      - "127.0.0.1:4566:4566" # Core LocalStack Gateway port
    environment:
      - SERVICES=s3,iam,sts,lambda,sqs
      - AWS_DEFAULT_REGION=us-east-1
      - DOCKER_HOST=unix:///var/run/docker.sock
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
    restart: unless-stopped

  # MinIO: S3-Compatible Object Storage for Bucket Security Testing
  minio_s3:
    image: minio/minio:latest
    container_name: lab_minio_s3
    networks:
      cloud_net:
        ipv4_address: 172.30.5.20
    ports:
      - "127.0.0.1:9000:9000" # S3 API endpoint
      - "127.0.0.1:9001:9001" # Web Console
    environment:
      - MINIO_ROOT_USER=LabCloudAdmin
      - MINIO_ROOT_PASSWORD=LabCloudSecretKey2026!
    command: server /data --console-address ":9001"
    restart: unless-stopped
```

### 6.2 Cloud Security Auditing CLI Commands
```bash
# 1. Configure AWS CLI to interact with LocalStack on loopback
export AWS_ACCESS_KEY_ID="test"
export AWS_SECRET_ACCESS_KEY="test"
export AWS_DEFAULT_REGION="us-east-1"
alias awslocal="aws --endpoint-url=http://127.0.0.1:4566"

# 2. Create intentionally misconfigured public S3 bucket
awslocal s3 mb s3://company-confidential-backups
awslocal s3api put-bucket-acl --bucket company-confidential-backups --acl public-read

# 3. Audit bucket permissions using AWS CLI
awslocal s3api get-bucket-acl --bucket company-confidential-backups
```

---

## 7. Automated Lab Health Check & Teardown Script

Sample lifecycle script (`lab_manager.sh`):
```bash
#!/usr/bin/env bash
# Master Lab Lifecycle Manager
set -e

ACTION="${1:-status}"

case "$ACTION" in
    start-all)
        echo "[*] Starting all Docker security enclaves..."
        docker compose -f docker-compose.level1.yml up -d
        docker compose -f docker-compose.level2.yml up -d
        docker compose -f docker-compose.level3.yml up -d
        docker compose -f docker-compose.level5.yml up -d
        echo "[+] All Docker enclaves started successfully."
        ;;
    stop-all)
        echo "[*] Stopping all Docker security enclaves..."
        docker compose -f docker-compose.level1.yml down
        docker compose -f docker-compose.level2.yml down
        docker compose -f docker-compose.level3.yml down
        docker compose -f docker-compose.level5.yml down
        echo "[+] All Docker enclaves stopped."
        ;;
    status)
        echo "[*] Current Active Lab Containers:"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        ;;
    *)
        echo "Usage: $0 {start-all|stop-all|status}"
        exit 1
        ;;
esac
```

---

## 8. Authoritative References

* **Docker Documentation**: *Networking in Compose & Port Binding Security* (`docs.docker.com`).
* **Vagrant by HashiCorp**: *Vagrantfile Documentation & Network Configuration* (`developer.hashicorp.com/vagrant`).
* **LocalStack Documentation**: *Local Cloud Development Platform* (`docs.localstack.cloud`).
* **OWASP Vulnerable Web Applications Directory (VWAD)**: *Catalog of Vulnerable Target Blueprints* (`owasp.org`).
