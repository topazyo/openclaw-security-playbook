# ClawdBot Seccomp Security Profiles

Production-ready seccomp profiles for ClawdBot Docker containers.

## Quick Start

```bash
# Docker Compose
docker-compose up -d

# Docker Run
docker run --security-opt seccomp=clawdbot.json your-image
