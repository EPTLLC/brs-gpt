# BRS-GPT Docker Guide

Docker deployment guide for BRS-GPT security scanner.

## Quick Start

### Build Image

```bash
docker build -t brs-gpt:latest .
```

### Run Basic Scan

```bash
docker run --rm \
  -e OPENAI_API_KEY=sk-your-key-here \
  -v $(pwd)/results:/app/results \
  brs-gpt:latest start example.com --profile lightning
```

## Docker Compose

### Basic Scan

```bash
# Set environment variables
export OPENAI_API_KEY=sk-your-key-here
export TARGET=example.com
export PROFILE=fast

# Run scan
docker-compose up brs-gpt
```

### Smart Mode (AI Orchestrator)

```bash
export OPENAI_API_KEY=sk-your-key-here
export TARGET=example.com
export PROFILE=balanced

docker-compose --profile smart up brs-gpt-smart
```

### Live Monitoring

```bash
export OPENAI_API_KEY=sk-your-key-here
export TARGET=example.com
export CYCLES=10
export INTERVAL=120

docker-compose --profile live up -d brs-gpt-live
```

### API Service

```bash
export OPENAI_API_KEY=sk-your-key-here
export BRS_GPT_API_KEY=your-api-key
export API_PORT=8000

docker-compose --profile api up -d brs-gpt-api
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key (required) | - |
| `OPENAI_MODEL` | Primary AI model | `gpt-4o` |
| `OPENAI_SEARCH_MODEL` | Search/OSINT model | `gpt-4o-mini-search-preview` |
| `TARGET` | Target domain | `example.com` |
| `PROFILE` | Scan profile | `lightning` |
| `CYCLES` | Monitoring cycles | `5` |
| `INTERVAL` | Seconds between cycles | `60` |
| `API_PORT` | API service port | `8000` |

## Volumes

| Volume | Purpose |
|--------|---------|
| `/app/results` | Scan results (HTML, JSON, SARIF) |
| `/app/output` | Additional output files |
| `/app/.config/brs-gpt` | Configuration and API keys |

## Advanced Usage

### Custom Configuration

```bash
docker run --rm \
  -e OPENAI_API_KEY=sk-your-key-here \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/config:/app/.config/brs-gpt \
  brs-gpt:latest start example.com --profile deep
```

### Pentest-as-Code

```bash
docker run --rm \
  -e OPENAI_API_KEY=sk-your-key-here \
  -v $(pwd)/scenarios:/app/scenarios \
  -v $(pwd)/results:/app/results \
  brs-gpt:latest pac /app/scenarios/web_api.yaml
```

### Network Scanning

```bash
docker run --rm \
  --network host \
  -e OPENAI_API_KEY=sk-your-key-here \
  -v $(pwd)/results:/app/results \
  brs-gpt:latest start 192.168.1.1 --profile fast
```

## CI/CD Integration

### GitLab CI

```yaml
security_scan:
  image: brs-gpt:latest
  script:
    - brs-gpt start $TARGET --profile fast
  artifacts:
    paths:
      - results/
```

### GitHub Actions

```yaml
- name: Run BRS-GPT
  uses: docker://brs-gpt:latest
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
  with:
    args: start example.com --profile lightning
```

## Troubleshooting

### Permission Issues

```bash
# Fix permissions
docker run --rm -v $(pwd)/results:/app/results \
  alpine chown -R 1000:1000 /app/results
```

### DNS Resolution

```bash
# Use host network for internal targets
docker run --rm --network host \
  -e OPENAI_API_KEY=sk-your-key-here \
  brs-gpt:latest start internal.example.com
```

### API Key Not Working

```bash
# Verify API key is set
docker run --rm \
  -e OPENAI_API_KEY=sk-your-key-here \
  brs-gpt:latest setup
```

## Security Considerations

1. Never commit API keys to version control
2. Use secrets management (Docker secrets, Kubernetes secrets)
3. Run as non-root user (default in image)
4. Limit container resources
5. Use private registry for production

## Production Deployment

### With Docker Secrets

```bash
echo "sk-your-key-here" | docker secret create openai_api_key -

docker service create \
  --name brs-gpt \
  --secret openai_api_key \
  --env OPENAI_API_KEY_FILE=/run/secrets/openai_api_key \
  brs-gpt:latest start example.com
```

### With Kubernetes

See `docs/KUBERNETES.md` for Kubernetes deployment guide.

---

**Note**: Docker is provided for convenience. For production bare-metal deployment, see main README.

