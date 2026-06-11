# Gaze Docker

> A lightweight web-based Docker management dashboard.

Single Go binary, no runtime dependencies besides Docker. Embedded SPA frontend with zero external assets.

## Features

- 📋 **Container Management** — list, start, stop, restart, remove, inspect
- 📡 **Real-time Logs** — WebSocket streaming with keyword/regex filter, highlight, download
- 🖼️ **Image Management** — list, delete, load .tar, browse image filesystem
- 🚀 **Deploy** — deploy via docker-compose YAML or `docker run`
- 📊 **Resource Monitoring** — CPU, memory, disk, container/image counts
- 📝 **Audit Log** — tracks all admin operations (image delete, deploy, container actions)
- 🌐 **i18n** — Chinese / English UI toggle
- 🔐 **Auth** — optional password auth with viewer/admin roles, auto-rotating passwords
- 🛡️ **Brute-force Protection** — 10 failed logins → fake page with mock data
- 🌗 **Dark / Light Theme**

## Quick Start

### Docker Compose (Recommended)

```bash
docker load -i gaze-docker.tar        # if using offline image
docker compose -f docker-compose.example.yml up -d
```

Open http://localhost:8080

### Binary

```bash
make build
./gaze-docker
```

### Docker Build

```bash
docker build -t gaze-docker:local .
docker run -d -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock gaze-docker:local
```

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-port` | `PORT` | `8080` | Web server listening port |
| `-auth` | `AUTH` | `false` | Enable password auth (`true`/`1`) |
| `-auth-rotate` | `AUTH_ROTATE` | `1h` | Password rotation interval |

When auth is enabled, startup logs show temporary passwords:

```
[AUTH] viewer password: xxxx
[AUTH] admin  password: yyyy
```

| Role | Capabilities |
|------|-------------|
| viewer | View containers and logs (sensitive containers hidden) |
| admin | Full access: images, deploy, container ops, audit |

## Build

```bash
make build              # current platform
make build-linux        # linux/amd64
make build-mac          # darwin/amd64
make build-mac-arm      # darwin/arm64

./build.sh              # interactive menu
./build.sh all          # all platforms
```

## Tech Stack

- **Backend**: Go 1.21, single file (`main.go`)
- **Frontend**: Vanilla HTML/CSS/JS, embedded via `//go:embed`
- **Runtime**: Docker CLI (shells out to `docker ps`, `docker logs`, `docker compose`, etc.)

## License

[MIT](LICENSE)
