# SAFECode-Web Backend

A production-ready security code analysis service with Semgrep static analysis and robust false-positive suppression system.

## Features

- **Static Analysis**: Semgrep integration with configurable rulesets
- **False-Positive Suppression**: 8 suppression types with safety gates
- **AI Integration**: Optional OpenAI GPT for enhanced analysis
- **Rate Limiting**: Sliding window rate limiting per client IP
- **Authentication**: Bearer token authentication
- **Caching**: In-memory caching with TTL
- **Compression**: Gzip compression for responses
- **UTF-8 Safety**: End-to-end UTF-8 handling and sanitization
- **Telemetry**: Comprehensive metrics and alerting
- **Baseline Management**: Scan result comparison and drift detection
- **Pagination**: Configurable result pagination
- **Health Checks**: Service health monitoring

## Quick Start

### Prerequisites

- Python 3.11+
- Semgrep CLI (optional, for full functionality)
- OpenAI API key (optional, for AI features)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

5. **Run the application**
   ```bash
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8001
   ```

### Docker

```bash
# Build image
docker build -t safecode-web-backend .

# Run container
docker run -p 8001:8001 --env-file .env safecode-web-backend
```

## API Usage

### Basic Scan

```bash
curl -X POST "http://localhost:8001/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "filename": "example.c",
    "code": "#include <stdio.h>\nint main() { printf(\"Hello\"); return 0; }",
    "ruleset": "p/security-audit"
  }'
```

### Authenticated Raw Scan

```bash
curl -X POST "http://localhost:8001/scan/raw" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-api-token" \
  -d '{
    "filename": "example.c",
    "code": "#include <stdio.h>\nint main() { printf(\"Hello\"); return 0; }"
  }'
```

### Health Check

```bash
curl http://localhost:8001/health
```

### Metrics

```bash
curl http://localhost:8001/metrics
```

### Alerts

```bash
curl http://localhost:8001/alerts
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFECODE_API_TOKEN` | - | API token for authentication |
| `SEMGREP_TIMEOUT` | 60 | Semgrep scan timeout (seconds) |
| `SEMGREP_JOBS` | 4 | Number of parallel Semgrep jobs |
| `SEMGREP_MAX_FINDINGS` | 250 | Maximum findings per scan |
| `SEMGREP_MAX_TARGET_BYTES` | 2000000 | Maximum target file size |
| `SAFE_MAX_FINDINGS_RESPONSE` | 200 | Maximum findings in response |
| `SAFE_MAX_INLINE_CODE_CHARS` | 20000 | Maximum code length |
| `SAFE_MAX_SNIPPET_CHARS` | 600 | Maximum snippet length |
| `RATE_LIMIT_REQUESTS` | 100 | Rate limit requests per window |
| `RATE_LIMIT_WINDOW` | 3600 | Rate limit window (seconds) |
| `ENABLE_GPT` | false | Enable AI processing |
| `OPENAI_API_KEY` | - | OpenAI API key |
| `OPENAI_MODEL` | gpt-4o-mini | OpenAI model to use |
| `CACHE_TTL_SECONDS` | 120 | Cache TTL (seconds) |
| `LOG_LEVEL` | info | Logging level |
| `HOST` | 0.0.0.0 | Server host |
| `PORT` | 8001 | Server port |

## Suppression Rules

The system includes 8 suppression types:

1. **printf_literal_format**: Suppress printf with literal format strings
2. **strncpy_bounds_plus_nul**: Suppress strncpy with proper bounds and null termination
3. **strncat_space_guard**: Suppress strncat with space guard
4. **execl_no_shell**: Suppress execl without shell
5. **overflow_guard**: Suppress integer overflow with guards
6. **free_then_null**: Suppress double free with null assignment
7. **null_guarded_use**: Suppress null pointer dereference with null check
8. **context_safe**: Suppress findings based on context analysis

### Safety Gates

The following functions are never suppressed:
- `strcpy`, `strcat`, `gets`, `sprintf`, `vsprintf`, `system`, `popen`

## Rate Limiting

The API implements sliding window rate limiting:
- Default: 100 requests per hour per IP
- Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- 429 status code when limit exceeded

## Pagination

Scan results support pagination:
- `limit`: Maximum findings to return (default: 200)
- `offset`: Offset for pagination (default: 0)
- Response includes pagination metadata

## Baseline Management

Create and compare baselines:
```bash
# Create baseline
curl -X POST "http://localhost:8001/baseline/my-repo/main" \
  -H "Authorization: Bearer your-api-token" \
  -H "Content-Type: application/json" \
  -d '{"filename": "example.c", "code": "..."}'

# Compare with baseline
curl -X POST "http://localhost:8001/scan?repo=my-repo&branch=main" \
  -H "Content-Type: application/json" \
  -d '{"filename": "example.c", "code": "..."}'
```

## Monitoring

### Health Check
- Endpoint: `GET /health`
- Returns service status and Semgrep version

### Metrics
- Endpoint: `GET /metrics`
- Returns telemetry data including scan statistics

### Alerts
- Endpoint: `GET /alerts`
- Returns security alerts based on thresholds

## Development

### Running Tests
```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run tests
pytest tests/
```

### Code Style
```bash
# Install linting tools
pip install black flake8

# Format code
black app/

# Lint code
flake8 app/
```

## Production Deployment

### Docker Compose
```yaml
version: '3.8'
services:
  safecode-backend:
    build: .
    ports:
      - "8001:8001"
    environment:
      - SAFECODE_API_TOKEN=${SAFECODE_API_TOKEN}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - ./baselines:/app/baselines
```

### Kubernetes
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safecode-backend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: safecode-backend
  template:
    metadata:
      labels:
        app: safecode-backend
    spec:
      containers:
      - name: safecode-backend
        image: safecode-web-backend:latest
        ports:
        - containerPort: 8001
        env:
        - name: SAFECODE_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: safecode-secrets
              key: api-token
```

## Troubleshooting

### Common Issues

1. **Semgrep not available**
   - Install Semgrep CLI: `pip install semgrep`
   - Or use Docker: `docker pull returntocorp/semgrep`

2. **OpenAI API errors**
   - Check API key configuration
   - Verify API key has sufficient credits
   - Check network connectivity

3. **Rate limiting**
   - Increase `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW`
   - Use authentication for higher limits

4. **Memory issues**
   - Reduce `SEMGREP_MAX_FINDINGS`
   - Increase `CACHE_TTL_SECONDS`
   - Monitor memory usage

### Logs

Enable debug logging:
```bash
export LOG_LEVEL=debug
python -m uvicorn app.main:app --log-level debug
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

[Add your license information here]
