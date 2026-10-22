#!/bin/bash
set -e
cd "$(dirname "$0")"

echo "╔═══════════════════════════════════════════════════╗"
echo "║  php2shell Lab Setup                              ║"
echo "║  CVE-2026-109618 / CVE-2026-109619                ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# ── Webroot ──────────────────────────────────────────────

mkdir -p webroot/app webroot/api

# Default endpoint — starts a session (used by most POCs/exploits)
cat > webroot/index.php << 'PHP'
<?php
session_start();
echo "PHP " . PHP_VERSION . "\n";
echo "SAPI " . php_sapi_name() . "\n";
echo "upload_progress " . ini_get('session.upload_progress.enabled') . "\n";
echo "OK\n";
PHP

# No-session endpoint (plain PHP, no session_start)
cat > webroot/nosession.php << 'PHP'
<?php
echo "PHP " . PHP_VERSION . "\nno session_start\n";
PHP

# LFI sink — simulates real-world include vulnerability
# (WordPress plugins, custom PHP apps, etc.)
cat > webroot/vuln.php << 'PHP'
<?php
$page = $_GET['page'] ?? 'home';
include($page);
PHP

# Session OOM endpoint — calls session_start() which decodes session file
# Used by Chain E: if session file is ~30MB, decode OOMs
cat > webroot/session_oom.php << 'PHP'
<?php
session_start();
echo "OK " . session_id() . "\n";
PHP

# php_serialize handler endpoint — sets session handler to php_serialize
# Used by Chain C: pollutes FPM worker's PS(serializer)
cat > webroot/app_serialize.php << 'PHP'
<?php
ini_set("session.serialize_handler", "php_serialize");
session_start();
$_SESSION["init"] = time();
echo "OK\n";
PHP

# __destruct gadget endpoint — defines Evil class and starts session
# Used by Chain C trigger: handler mismatch deserializes injected object
cat > webroot/destruct_test.php << 'PHP'
<?php
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            system($this->cmd);
        }
    }
}
session_start();
echo "OK\n";
PHP

# OOM trigger endpoint — allocates until memory exhausted
# Used by Chain D/E testing
cat > webroot/fatal.php << 'PHP'
<?php
$x = str_repeat("A", 64 * 1024 * 1024);
echo "OK";
PHP

# ── Per-directory session handlers (Chain C) ─────────────

# /app/ uses php_serialize handler
echo "session.serialize_handler = php_serialize" > webroot/app/.user.ini
cat > webroot/app/upload.php << 'PHP'
<?php
echo "PHP " . PHP_VERSION . "\nhandler: php_serialize\n";
PHP

# /api/ uses default php handler + defines the Evil gadget class
echo "session.serialize_handler = php" > webroot/api/.user.ini
cat > webroot/api/endpoint.php << 'PHP'
<?php
class Evil {
    public $cmd;
    public function __destruct() {
        if ($this->cmd) {
            file_put_contents("/tmp/rce_proof.txt", shell_exec($this->cmd), FILE_APPEND);
        }
    }
}
session_start();
echo "OK\n";
PHP

# ── PHP config (FPM) ────────────────────────────────────

cat > php.ini << 'INI'
[Session]
session.save_handler = files
session.save_path = /tmp/sessions
session.use_strict_mode = 0
session.use_cookies = 1
session.use_only_cookies = 0
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off
session.upload_progress.prefix = upload_progress_
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
session.upload_progress.freq = 1%
session.upload_progress.min_freq = 0

[PHP]
display_errors = On
error_reporting = E_ALL
max_execution_time = 60
post_max_size = 128M
upload_max_filesize = 128M
file_uploads = On
memory_limit = 32M
INI

# ── PHP config (Apache mod_php) ─────────────────────────

cat > php-apache.ini << 'INI'
; Low memory_limit to make OOM easy to trigger (Chain D)
memory_limit = 32M
post_max_size = 256M
upload_max_filesize = 256M
max_input_vars = 100000
max_file_uploads = 100000
display_errors = On
error_reporting = E_ALL
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off
session.save_path = /tmp
INI

# ── Nginx config ────────────────────────────────────────

cat > nginx.conf << 'NGINX'
server {
    listen 80;
    root /var/www/html;
    index index.php;
    client_max_body_size 128m;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        fastcgi_pass php-fpm:9000;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 120;
        fastcgi_request_buffering off;
    }
}
NGINX

# ── FPM pool config (single worker for Chain E) ────────

cat > www.conf << 'FPM'
[www]
user = www-data
group = www-data
listen = 9000
pm = static
pm.max_children = 1
FPM

# ── Docker Compose ──────────────────────────────────────

cat > docker-compose.yml << 'YAML'
services:
  # PHP-FPM (Chains A, B, C, E)
  php-fpm:
    image: php:8.2.33-fpm
    container_name: php2shell-fpm
    volumes:
      - ./webroot:/var/www/html
      - ./php.ini:/usr/local/etc/php/php.ini
      - ./www.conf:/usr/local/etc/php-fpm.d/www.conf
    security_opt: [seccomp:unconfined]
    privileged: true
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && php-fpm"

  # Nginx reverse proxy → PHP-FPM
  nginx:
    image: nginx:alpine
    container_name: php2shell-nginx
    ports: ["18080:80"]
    volumes:
      - ./webroot:/var/www/html
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
    depends_on: [php-fpm]

  # Apache mod_php (Chain D — OOM)
  apache:
    image: php:8.2.33-apache
    container_name: php2shell-apache
    ports: ["18081:80"]
    volumes:
      - ./webroot:/var/www/html
      - ./php-apache.ini:/usr/local/etc/php/php.ini
    command: >
      bash -c "mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions && apache2-foreground"
YAML

# ── Start ───────────────────────────────────────────────

echo "Starting containers..."
docker compose up -d

# Wait for services
echo "Waiting for services..."
sleep 3

# Verify
echo ""
echo "Verifying..."
FPM=$(curl -sf http://127.0.0.1:18080/index.php 2>/dev/null | head -1)
APACHE=$(curl -sf http://127.0.0.1:18081/index.php 2>/dev/null | head -1)
echo "  FPM+nginx : ${FPM:-FAILED} (http://127.0.0.1:18080)"
echo "  Apache    : ${APACHE:-FAILED} (http://127.0.0.1:18081)"

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║  Lab ready!                                       ║"
echo "╠═══════════════════════════════════════════════════╣"
echo "║                                                   ║"
echo "║  FPM + nginx  → http://127.0.0.1:18080            ║"
echo "║  Apache mod_php → http://127.0.0.1:18081          ║"
echo "║                                                   ║"
echo "║  Verify:                                          ║"
echo "║    cd ../poc                                      ║"
echo "║    python3 verify_session_injection.py             ║"
echo "║    python3 verify_handler_mismatch.py              ║"
echo "║    python3 verify_oom_trigger.py --port 18081      ║"
echo "║    python3 verify_fpm_stale_state.py               ║"
echo "║                                                   ║"
echo "║  Exploit:                                         ║"
echo "║    cd ../exploit                                  ║"
echo "║    python3 chain_a_session_lfi.py --port 18080     ║"
echo "║    python3 chain_c_mismatch_rce.py --port 18080    ║"
echo "║                                                   ║"
echo "╚═══════════════════════════════════════════════════╝"
