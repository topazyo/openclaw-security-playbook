# Common Issues and Solutions

> **Quick Reference:** General troubleshooting guide for ClawdBot operational issues

This guide covers common operational issues with ClawdBot, including installation, configuration, runtime errors, and performance problems.

---

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [Configuration Issues](#configuration-issues)
3. [Startup and Runtime Errors](#startup-and-runtime-errors)
4. [API Connection Issues](#api-connection-issues)
5. [Authentication Errors](#authentication-errors)
6. [Performance Issues](#performance-issues)
7. [Docker Container Issues](#docker-container-issues)
8. [Network and Proxy Issues](#network-and-proxy-issues)
9. [Logging and Debugging](#logging-and-debugging)
10. [Resource Exhaustion](#resource-exhaustion)

---

## Installation Issues

### Issue: Python Version Incompatible

**Symptom:**
```bash
$ python --version
Python 2.7.18
$ pip install clawdbot
ERROR: Package 'clawdbot' requires a different Python: 2.7.18 not in '>=3.9'
```

**Cause:** ClawdBot requires Python 3.9 or higher

**Solution:**
```bash
# Check Python version
python3 --version

# If Python 3.9+ not installed, install it:

# macOS
brew install python@3.11

# Ubuntu/Debian
sudo apt update
sudo apt install python3.11 python3.11-pip python3.11-venv

# Fedora/RHEL
sudo dnf install python3.11

# Create virtual environment with correct Python
python3.11 -m venv clawdbot-env
source clawdbot-env/bin/activate

# Verify Python version
python --version  # Should show 3.11.x

# Install ClawdBot
pip install clawdbot
```

---

### Issue: Permission Denied During Installation

**Symptom:**
```bash
$ pip install clawdbot
ERROR: Could not install packages due to an OSError: [Errno 13] Permission denied: '/usr/local/lib/python3.11/site-packages/'
```

**Cause:** Attempting to install to system Python without sudo

**Solution:**
```bash
# Option 1: Use virtual environment (RECOMMENDED)
python3 -m venv clawdbot-env
source clawdbot-env/bin/activate
pip install clawdbot

# Option 2: User installation
pip install --user clawdbot

# Option 3: System installation (not recommended)
sudo pip install clawdbot
```

---

### Issue: Dependency Conflicts

**Symptom:**
```bash
$ pip install clawdbot
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed.
  anthropic 0.25.0 requires httpx>=0.23.0, but you have httpx 0.22.0.
```

**Cause:** Conflicting package versions

**Solution:**
```bash
# Create fresh virtual environment
python3 -m venv clawdbot-env-clean
source clawdbot-env-clean/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install ClawdBot (will resolve dependencies)
pip install clawdbot

# If conflicts persist, install with constraints
pip install clawdbot --constraint constraints.txt

# Or upgrade conflicting package
pip install --upgrade httpx
pip install clawdbot
```

---

### Issue: SSL Certificate Errors During Installation

**Symptom:**
```bash
$ pip install clawdbot
SSL: CERTIFICATE_VERIFY_FAILED
```

**Cause:** SSL certificate validation issues

**Solution:**
```bash
# Option 1: Update CA certificates (RECOMMENDED)
# macOS
/Applications/Python\ 3.11/Install\ Certificates.command

# Ubuntu/Debian
sudo apt-get install ca-certificates
sudo update-ca-certificates

# Option 2: Use system certificates
pip install --cert /etc/ssl/certs/ca-certificates.crt clawdbot

# Option 3: Temporary workaround (NOT RECOMMENDED for production)
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org clawdbot
```

---

## Configuration Issues

### Issue: Configuration File Not Found

**Symptom:**
```bash
$ clawdbot start
Error: Configuration file not found: /home/user/.openclaw/config/openclaw-agent.yml
```

**Cause:** Configuration file missing or in wrong location

**Solution:**
```bash
# Check expected locations
ls -la ~/.openclaw/config/
ls -la ~/.config/openclaw/

# Create configuration directory
mkdir -p ~/.openclaw/config

# Copy example configuration
cp /path/to/clawdbot/examples/openclaw-agent.yml ~/.openclaw/config/

# Or specify custom config location
clawdbot start --config /path/to/custom/config.yml

# Verify configuration loads
clawdbot config validate
```

---

### Issue: Invalid YAML Syntax

**Symptom:**
```bash
$ clawdbot start
Error: Invalid YAML syntax in configuration file:
  while parsing a block mapping
  expected <block end>, but found '<block mapping start>'
  in "/home/user/.openclaw/config/openclaw-agent.yml", line 15, column 3
```

**Cause:** YAML indentation or syntax error

**Solution:**
```bash
# Validate YAML syntax
python3 -c "import yaml; yaml.safe_load(open('~/.openclaw/config/openclaw-agent.yml'))"

# Common YAML issues:
# 1. Mixed tabs and spaces (use spaces only)
# 2. Incorrect indentation (use 2 spaces per level)
# 3. Missing colon after key
# 4. Unquoted special characters

# Example fixes:

# WRONG:
server:
	port: 8443  # Tab used

# RIGHT:
server:
  port: 8443  # 2 spaces

# WRONG:
api_key: sk-ant-abc:def  # Colon in value

# RIGHT:
api_key: "sk-ant-abc:def"  # Quoted

# Use YAML linter
pip install yamllint
yamllint ~/.openclaw/config/openclaw-agent.yml
```

---

### Issue: Environment Variables Not Loaded

**Symptom:**
```bash
$ clawdbot start
Error: ANTHROPIC_API_KEY not found in configuration or environment
```

**Cause:** Environment variables not set or not loaded

**Solution:**
```bash
# Check if environment variable is set
echo $ANTHROPIC_API_KEY

# Set environment variable (temporary)
read -s -p "Enter ANTHROPIC_API_KEY: " ANTHROPIC_API_KEY && echo
export ANTHROPIC_API_KEY

# Add to shell profile (persistent)
echo '# export ANTHROPIC_API_KEY from your OS keychain in shell startup' >> ~/.bashrc
source ~/.bashrc

# Or use .env file
# Generate: openssl rand -base64 32
cat > ~/.openclaw/.env << EOF
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
OPENAI_API_KEY=${OPENAI_API_KEY}
EOF

# Load .env file
set -a
source ~/.openclaw/.env
set +a

# Or specify in configuration file
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
credentials:
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
EOF
```

---

### Issue: Invalid Configuration Values

**Symptom:**
```bash
$ clawdbot start
Error: Invalid value for 'server.port': must be between 1 and 65535
```

**Cause:** Configuration value out of valid range

**Solution:**
```bash
# Validate configuration
clawdbot config validate --verbose

# Common validation errors and fixes:

# Port out of range
# WRONG: port: 70000
# RIGHT: port: 8443

# Invalid IP address
# WRONG: host: "256.1.1.1"
# RIGHT: host: "127.0.0.1"

# Invalid timeout
# WRONG: timeout: -1
# RIGHT: timeout: 30

# Invalid log level
# WRONG: log_level: "VERBOSE"
# RIGHT: log_level: "DEBUG" or "INFO"

# Check configuration schema
clawdbot config schema
```

---

## Startup and Runtime Errors

### Issue: ClawdBot Won't Start

**Symptom:**
```bash
$ clawdbot start
Starting ClawdBot...
Error: Failed to start server
```

**Cause:** Multiple possible causes

**Solution:**
```bash
# Check detailed error logs
clawdbot start --verbose

# Common causes:

# 1. Port already in use
sudo lsof -i :8443
# Kill conflicting process
kill -9 <PID>

# 2. Permission denied (binding to port < 1024)
# Use port >= 1024 or run with sudo
clawdbot start --port 8443

# 3. Missing dependencies
pip install -r requirements.txt

# 4. Corrupted installation
pip uninstall clawdbot
pip install --no-cache-dir clawdbot

# 5. Check system resources
df -h  # Disk space
free -h  # Memory
top  # CPU usage

# Start in debug mode
clawdbot start --debug --log-level DEBUG
```

---

### Issue: Module Import Errors

**Symptom:**
```bash
$ clawdbot start
Traceback (most recent call last):
  File "/usr/local/bin/clawdbot", line 5, in <module>
    from clawdbot.cli import main
ModuleNotFoundError: No module named 'anthropic'
```

**Cause:** Missing Python dependencies

**Solution:**
```bash
# Verify virtual environment is activated
which python  # Should point to venv

# If not activated
source clawdbot-env/bin/activate

# Reinstall dependencies
pip install -r requirements.txt

# Or reinstall ClawdBot
pip install --force-reinstall clawdbot

# Check installed packages
pip list | grep anthropic

# If specific package missing
pip install anthropic openai httpx
```

---

### Issue: Process Crashes on Startup

**Symptom:**
```bash
$ clawdbot start
Starting ClawdBot...
Segmentation fault (core dumped)
```

**Cause:** Low-level library issue or memory corruption

**Solution:**
```bash
# Check system logs
sudo dmesg | tail -50
journalctl -xe

# Common causes:

# 1. Incompatible system libraries
# Update system packages
sudo apt update && sudo apt upgrade  # Ubuntu/Debian
brew upgrade  # macOS

# 2. Corrupted Python installation
python3 -m ensurepip --upgrade
pip install --upgrade pip setuptools wheel

# 3. Memory issues
# Check available memory
free -h
# Increase swap if needed
sudo fallocate -l 2G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# 4. Rebuild dependencies
pip uninstall clawdbot
pip cache purge
pip install --no-cache-dir clawdbot

# Run with debugger
python -m pdb $(which clawdbot) start
```

---

## API Connection Issues

### Issue: Connection Timeout

**Symptom:**
```bash
$ clawdbot test
Error: Connection timeout when connecting to Anthropic API
Timeout: 30 seconds
```

**Cause:** Network issues or slow connection

**Solution:**
```bash
# Test connectivity
ping api.anthropic.com
curl -I https://api.anthropic.com

# Increase timeout in configuration
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
api:
  timeout: 60  # Increase from 30 to 60 seconds
  retry:
    max_attempts: 5
    backoff_factor: 2
EOF

# Test with curl
curl -X POST https://api.anthropic.com/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  --max-time 60 \
  -d '{
    "model": "claude-3-sonnet-20240229",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello"}]
  }'

# Check proxy settings
echo $HTTP_PROXY
echo $HTTPS_PROXY

# Disable proxy if causing issues
unset HTTP_PROXY HTTPS_PROXY
```

---

### Issue: SSL/TLS Verification Failed

**Symptom:**
```bash
$ clawdbot test
Error: SSL certificate verification failed
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed
```

**Cause:** SSL certificate validation issues

**Solution:**
```bash
# Update CA certificates
# Ubuntu/Debian
sudo apt-get install --reinstall ca-certificates

# macOS
# Download and install latest certificates
curl https://curl.se/ca/cacert.pem -o /usr/local/etc/openssl/cert.pem

# Verify SSL connection
openssl s_client -connect api.anthropic.com:443 -showcerts

# If behind corporate proxy with SSL inspection
# Configure custom CA bundle
export SSL_CERT_FILE=/path/to/corporate-ca-bundle.crt
export REQUESTS_CA_BUNDLE=/path/to/corporate-ca-bundle.crt

# Or in ClawdBot configuration
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
api:
  verify_ssl: true
  ca_bundle: /path/to/ca-bundle.crt
EOF

# TEMPORARY WORKAROUND (NOT for production)
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
api:
  verify_ssl: false  # WARNING: Insecure
EOF
```

---

### Issue: Rate Limiting

**Symptom:**
```bash
$ clawdbot test
Error: Rate limit exceeded
Status: 429
Retry-After: 60
```

**Cause:** Too many requests to API

**Solution:**
```bash
# Check rate limits in API dashboard
# Anthropic: https://console.anthropic.com/settings/limits
# OpenAI: https://platform.openai.com/account/rate-limits

# Configure rate limiting in ClawdBot
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
api:
  rate_limiting:
    enabled: true
    requests_per_minute: 50
    tokens_per_minute: 40000
    retry_on_429: true
    backoff_multiplier: 2
EOF

# Implement exponential backoff
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
api:
  retry:
    max_attempts: 5
    initial_delay: 1
    max_delay: 60
    exponential_base: 2
EOF

# Monitor API usage
clawdbot stats --show-api-usage
```

---

## Authentication Errors

### Issue: Invalid API Key

**Symptom:**
```bash
$ clawdbot test
Error: Invalid API key
Status: 401
Message: Authentication failed
```

**Cause:** API key is incorrect, expired, or revoked

**Solution:**
```bash
# Verify API key format
echo $ANTHROPIC_API_KEY
# Anthropic: sk-ant-api03-...
# OpenAI: sk-...

# Check key length and format
if [[ $ANTHROPIC_API_KEY =~ ^sk-ant- ]]; then
    echo "Format OK"
else
    echo "Invalid format"
fi

# Test API key directly
curl https://api.anthropic.com/v1/messages \
  -H "Content-Type: application/json" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -d '{"model":"claude-3-sonnet-20240229","max_tokens":1,"messages":[{"role":"user","content":"test"}]}'

# Generate new API key if needed
# Anthropic: https://console.anthropic.com/settings/keys
# OpenAI: https://platform.openai.com/api-keys

# Update configuration
# Option 1: Environment variable
export ANTHROPIC_API_KEY="sk-ant-NEW_KEY"

# Option 2: OS keychain (recommended)
# macOS
security add-generic-password \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -w "sk-ant-NEW_KEY"

# Option 3: Configuration file (less secure)
# Use credential isolation instead
```

---

### Issue: Insufficient Permissions

**Symptom:**
```bash
$ clawdbot invoke --model claude-opus-4
Error: Model not available
Status: 403
Message: Your API key does not have access to this model
```

**Cause:** API key lacks permissions for requested resource

**Solution:**
```bash
# Check account tier and model access
# Anthropic Console: https://console.anthropic.com/settings/plans
# OpenAI Dashboard: https://platform.openai.com/account/limits

# Use available model
clawdbot models list
clawdbot invoke --model claude-3-sonnet-20240229

# Upgrade account if needed
# Or request access to specific models

# Configure fallback models
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
models:
  primary: "claude-3-opus-20240229"
  fallback:
    - "claude-3-sonnet-20240229"
    - "claude-3-haiku-20240307"
EOF
```

---

## Performance Issues

### Issue: Slow Response Times

**Symptom:**
```bash
$ clawdbot invoke --prompt "Hello"
[Takes 30+ seconds]
Response: Hello! How can I help you?
```

**Cause:** Network latency, large context, or resource constraints

**Solution:**
```bash
# 1. Check network latency
ping api.anthropic.com
traceroute api.anthropic.com

# 2. Reduce context size
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
agent:
  max_context_tokens: 4096  # Reduce from default
  streaming: true  # Enable streaming for faster perceived response
EOF

# 3. Use faster model
clawdbot invoke --model claude-3-haiku-20240307

# 4. Enable caching (if supported)
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
caching:
  enabled: true
  ttl: 3600
  max_size: 1000
EOF

# 5. Monitor performance
clawdbot stats --show-latency

# 6. Profile bottlenecks
clawdbot start --profile --output profile.stats
```

---

### Issue: High Memory Usage

**Symptom:**
```bash
$ top
  PID USER   %CPU %MEM     VSZ    RSS COMMAND
 1234 user   80.0 90.0 8192000 7200000 python clawdbot
```

**Cause:** Memory leak or large context accumulation

**Solution:**
```bash
# Check memory usage
ps aux | grep clawdbot
free -h

# Configure memory limits
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
performance:
  memory:
    max_heap_size: "2G"
    max_context_cache: 100  # Limit cached contexts
    gc_threshold: 0.8  # Trigger GC at 80% usage
EOF

# Clear context periodically
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
agent:
  context:
    max_history: 10  # Keep only last 10 messages
    auto_summarize: true  # Summarize old context
EOF

# Run with memory profiling
pip install memory_profiler
python -m memory_profiler $(which clawdbot) start

# Restart periodically (systemd)
cat > /etc/systemd/system/clawdbot.service << 'EOF'
[Service]
RuntimeMaxSec=86400  # Restart after 24 hours
EOF

# Monitor memory over time
while true; do
  ps -p $(pgrep clawdbot) -o %mem,rss,vsz >> memory.log
  sleep 60
done
```

---

### Issue: High CPU Usage

**Symptom:**
```bash
$ top
%CPU: clawdbot process using 100% CPU constantly
```

**Cause:** Busy loop, inefficient processing, or polling

**Solution:**
```bash
# Profile CPU usage
pip install py-spy
sudo py-spy top --pid $(pgrep clawdbot)

# Record flame graph
sudo py-spy record -o profile.svg --pid $(pgrep clawdbot)

# Common fixes:

# 1. Disable polling (use webhooks)
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
server:
  mode: "webhook"  # Instead of "polling"
EOF

# 2. Increase sleep intervals
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
agent:
  poll_interval: 1.0  # Increase from 0.1
EOF

# 3. Limit concurrent requests
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
server:
  max_concurrent_requests: 10
  worker_threads: 4
EOF

# 4. Enable async mode
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
server:
  async: true
  async_workers: 4
EOF
```

---

## Docker Container Issues

### Issue: Container Won't Start

**Symptom:**
```bash
$ docker run clawdbot/clawdbot:latest
docker: Error response from daemon: OCI runtime create failed
```

**Cause:** Docker configuration or image issues

**Solution:**
```bash
# Check Docker is running
docker ps
docker info

# Pull latest image
docker pull clawdbot/clawdbot:latest

# Check image exists
docker images | grep clawdbot

# View container logs
docker logs <container_id>

# Run with detailed output
docker run --rm -it clawdbot/clawdbot:latest /bin/bash

# Check resource limits
docker run --memory="512m" --cpus="1.0" clawdbot/clawdbot:latest

# Verify port mapping
docker run -p 8443:8443 clawdbot/clawdbot:latest
```

---

### Issue: Volume Mount Permissions

**Symptom:**
```bash
$ docker run -v ~/.openclaw:/app/.openclaw clawdbot/clawdbot
Error: Permission denied: '/app/.openclaw/config/openclaw-agent.yml'
```

**Cause:** User ID mismatch between host and container

**Solution:**
```bash
# Check user IDs
id  # Host UID/GID
docker run clawdbot/clawdbot id  # Container UID/GID

# Fix permissions on host
sudo chown -R 1000:1000 ~/.openclaw

# Or run container as host user
docker run --user $(id -u):$(id -g) \
  -v ~/.openclaw:/app/.openclaw \
  clawdbot/clawdbot

# Or use named volume
docker volume create clawdbot-data
docker run -v clawdbot-data:/app/.openclaw clawdbot/clawdbot

# Set permissions in Dockerfile
USER 1000:1000
```

---

### Issue: Container Network Issues

**Symptom:**
```bash
$ docker run clawdbot/clawdbot
Error: Failed to connect to api.anthropic.com
```

**Cause:** Network isolation or DNS issues

**Solution:**
```bash
# Test network from container
docker run --rm clawdbot/clawdbot ping api.anthropic.com
docker run --rm clawdbot/clawdbot curl -I https://api.anthropic.com

# Use host network (removes isolation)
docker run --network host clawdbot/clawdbot

# Configure DNS
docker run --dns 8.8.8.8 --dns 8.8.4.4 clawdbot/clawdbot

# Check Docker network
docker network ls
docker network inspect bridge

# Create custom network
docker network create clawdbot-net
docker run --network clawdbot-net clawdbot/clawdbot

# Configure proxy if needed
docker run \
  -e HTTP_PROXY=http://proxy.corp:3128 \
  -e HTTPS_PROXY=http://proxy.corp:3128 \
  clawdbot/clawdbot
```

---

## Network and Proxy Issues

### Issue: Corporate Proxy Blocking Requests

**Symptom:**
```bash
$ clawdbot test
Error: Proxy connection failed
407 Proxy Authentication Required
```

**Cause:** Corporate proxy requiring authentication

**Solution:**
```bash
# Configure proxy with authentication
export HTTP_PROXY="http://username:password@proxy.corp:3128"
export HTTPS_PROXY="http://username:password@proxy.corp:3128"
export NO_PROXY="localhost,127.0.0.1"

# Or in configuration
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
proxy:
  http: "http://username:password@proxy.corp:3128"
  https: "http://username:password@proxy.corp:3128"
  no_proxy:
    - "localhost"
    - "127.0.0.1"
    - "*.internal.corp"
EOF

# Test proxy
curl -x http://proxy.corp:3128 https://api.anthropic.com

# For NTLM authentication
pip install python-ntlm
export HTTP_PROXY="http://domain\\username:password@proxy.corp:3128"

# Use proxy auto-config (PAC)
export HTTP_PROXY_PAC="http://proxy.corp/proxy.pac"
```

---

### Issue: Firewall Blocking Outbound Connections

**Symptom:**
```bash
$ clawdbot test
Error: Connection refused
Cannot connect to api.anthropic.com:443
```

**Cause:** Firewall blocking HTTPS connections

**Solution:**
```bash
# Test connectivity
telnet api.anthropic.com 443
nc -zv api.anthropic.com 443

# Check firewall rules
# Ubuntu/Debian
sudo ufw status
sudo iptables -L -n

# Allow outbound HTTPS
sudo ufw allow out 443/tcp
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# macOS
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Configure ClawdBot to use allowed ports
# Or request firewall rule from IT department

# Whitelist API endpoints:
# - api.anthropic.com (443)
# - api.openai.com (443)
```

---

## Logging and Debugging

### Issue: Logs Not Generated

**Symptom:**
```bash
$ ls ~/.openclaw/logs/
ls: cannot access '~/.openclaw/logs/': No such file or directory
```

**Cause:** Logging not configured or permissions issues

**Solution:**
```bash
# Create log directory
mkdir -p ~/.openclaw/logs
chmod 755 ~/.openclaw/logs

# Configure logging
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
logging:
  level: INFO
  format: json
  output:
    - file: ~/.openclaw/logs/clawdbot.log
    - console: true
  rotation:
    max_size: 100M
    max_files: 10
EOF

# Test logging
clawdbot start --log-level DEBUG

# Check log output
tail -f ~/.openclaw/logs/clawdbot.log

# Enable all debug logging
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
logging:
  level: DEBUG
  loggers:
    anthropic: DEBUG
    httpx: DEBUG
    clawdbot: DEBUG
EOF
```

---

### Issue: Logs Too Verbose

**Symptom:**
```bash
$ ls -lh ~/.openclaw/logs/clawdbot.log
-rw-r--r-- 1 user user 5.2G Feb 14 14:30 clawdbot.log
```

**Cause:** Debug logging enabled or no log rotation

**Solution:**
```bash
# Reduce log level
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
logging:
  level: INFO  # Change from DEBUG

  # Silence verbose libraries
  loggers:
    httpx: WARNING
    urllib3: WARNING
EOF

# Enable log rotation
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
logging:
  rotation:
    enabled: true
    max_size: 100M
    max_files: 5
    compress: true
EOF

# Manually rotate logs
mv ~/.openclaw/logs/clawdbot.log \
   ~/.openclaw/logs/clawdbot.log.$(date +%Y%m%d)
gzip ~/.openclaw/logs/clawdbot.log.*

# Clean old logs
find ~/.openclaw/logs -name "*.log.*" -mtime +30 -delete

# Use logrotate (Linux)
cat > /etc/logrotate.d/clawdbot << 'EOF'
/home/user/.openclaw/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
}
EOF
```

---

## Resource Exhaustion

### Issue: Disk Space Full

**Symptom:**
```bash
$ clawdbot start
Error: No space left on device
```

**Cause:** Logs, cache, or data filling disk

**Solution:**
```bash
# Check disk usage
df -h
du -sh ~/.openclaw/*

# Clean log files
find ~/.openclaw/logs -name "*.log" -mtime +7 -delete
find ~/.openclaw/logs -name "*.gz" -mtime +30 -delete

# Clean cache
rm -rf ~/.openclaw/cache/*

# Clean old backups
rm -rf ~/.openclaw/backups/credentials/credentials_backup_*

# Find large files
find ~/.openclaw -type f -size +100M -exec ls -lh {} \;

# Configure storage limits
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
storage:
  cache:
    max_size: 1G
  logs:
    max_total_size: 500M
  backups:
    retention_days: 30
EOF
```

---

### Issue: File Descriptor Limit

**Symptom:**
```bash
$ clawdbot start
Error: Too many open files
OSError: [Errno 24] Too many open files
```

**Cause:** Process opened too many files/sockets

**Solution:**
```bash
# Check current limits
ulimit -n

# Increase temporarily
ulimit -n 4096

# Increase permanently
# Add to /etc/security/limits.conf:
*  soft  nofile  4096
*  hard  nofile  8192

# Or systemd service
cat >> /etc/systemd/system/clawdbot.service << 'EOF'
[Service]
LimitNOFILE=8192
EOF

# Check open files
lsof -p $(pgrep clawdbot) | wc -l

# Fix file descriptor leaks in code
# Ensure files/sockets are properly closed
```

---

### Issue: Out of Memory

**Symptom:**
```bash
$ clawdbot start
Killed
# Or
MemoryError
```

**Cause:** Insufficient system memory

**Solution:**
```bash
# Check memory usage
free -h
top

# Increase swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Add to /etc/fstab for persistence:
/swapfile none swap sw 0 0

# Configure memory limits
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
performance:
  memory:
    max_heap_size: "1G"
    gc_threshold: 0.7
EOF

# Use systemd memory limits
cat >> /etc/systemd/system/clawdbot.service << 'EOF'
[Service]
MemoryMax=2G
MemoryHigh=1.5G
EOF

# Monitor memory usage
watch -n 1 'ps aux | grep clawdbot'
```

---

## Quick Diagnostic Commands

### System Health Check
```bash
# Full diagnostic
clawdbot doctor

# Check configuration
clawdbot config validate

# Test API connectivity
clawdbot test --all-providers

# Check permissions
ls -la ~/.openclaw/
ls -la /etc/wireguard/  # If using VPN

# View recent errors
tail -100 ~/.openclaw/logs/clawdbot.log | grep ERROR

# Check resource usage
ps aux | grep clawdbot
df -h ~/.openclaw
```

### Debug Mode
```bash
# Start with full debugging
clawdbot start \
  --debug \
  --verbose \
  --log-level DEBUG \
  --no-daemon

# Enable request logging
cat >> ~/.openclaw/config/openclaw-agent.yml << 'EOF'
debugging:
  log_requests: true
  log_responses: true
  log_headers: true
EOF
```

---

## Getting Help

### Information to Provide

When requesting support, include:

```bash
# System information
uname -a
python --version
pip list | grep clawdbot

# Configuration (sanitize sensitive data)
cat ~/.openclaw/config/openclaw-agent.yml | grep -v api_key

# Recent logs
tail -100 ~/.openclaw/logs/clawdbot.log

# Error details
# Copy full error message and stack trace

# Steps to reproduce
# Describe exact steps that cause the issue
```

### Support Channels
- **GitHub Issues:** https://github.com/YOUR-ORG/clawdbot-security-playbook/issues
- **Documentation:** `docs/guides/01-quick-start.md`
- **Security Issues:** security@company.com

---

**Last Updated:** February 14, 2026  
**Related Guides:**
- [Verification Failures](verification-failures.md)
- [Migration Failures](migration-failures.md)
- [Quick Start Guide](../guides/01-quick-start.md)
