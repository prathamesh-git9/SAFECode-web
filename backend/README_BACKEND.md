# SAFECode-Web Backend

A production-ready security code analysis service with **Flawfinder** static analysis and robust false-positive suppression system.

## Features

- **Dual Analyzer Support**: Flawfinder (primary) and Semgrep (legacy)
- **Advanced Suppression System**: 24 comprehensive false-positive suppression rules
- **AI Integration**: OpenAI GPT for enhanced analysis and code fixing
- **Rate Limiting**: Per-client IP rate limiting with sliding window
- **Authentication**: Bearer token authentication
- **UTF-8 Safety**: End-to-end UTF-8 handling
- **Telemetry**: Comprehensive metrics and alerting
- **Baseline Management**: Drift detection and comparison
- **Caching**: In-memory caching with TTL
- **Gzip Compression**: Automatic response compression

## Quick Start

### Prerequisites

- Python 3.11+
- Flawfinder (C/C++ static analysis tool)
- OpenAI API key (optional, for AI features)

### Installation

1. **Install Flawfinder**:
   ```bash
   # Using pip (recommended)
   pip install flawfinder
   
   # Or using system package manager
   # Ubuntu/Debian: sudo apt-get install flawfinder
   # CentOS/RHEL: sudo yum install flawfinder
   # macOS: brew install flawfinder
   ```

2. **Clone and setup**:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or: venv\Scripts\activate  # Windows
   
   pip install -r requirements.txt
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Start the server**:
   ```bash
   python -m uvicorn app.main:app --host 0.0.0.0 --port 8001
   ```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ANALYZER` | `flawfinder` | Analyzer to use: `flawfinder` or `semgrep` |
| `FLAWFINDER_PATH` | `flawfinder` | Path to Flawfinder executable |
| `FLAWFINDER_MAX_FINDINGS` | `1000` | Maximum findings to return |
| `FLAWFINDER_TIMEOUT` | `60` | Flawfinder scan timeout (seconds) |
| `SAFECODE_API_TOKEN` | `test-token` | API authentication token |
| `ENABLE_GPT` | `false` | Enable AI processing |
| `OPENAI_API_KEY` | `` | OpenAI API key |
| `OPENAI_MODEL` | `gpt-4o-mini` | OpenAI model to use |
| `RATE_LIMIT_REQUESTS` | `100` | Requests per hour per IP |
| `RATE_LIMIT_WINDOW` | `3600` | Rate limit window (seconds) |
| `SAFE_MAX_FINDINGS_RESPONSE` | `200` | Max findings in response |
| `SAFE_MAX_INLINE_CODE_CHARS` | `20000` | Max code length |
| `SAFE_MAX_SNIPPET_CHARS` | `600` | Max snippet length |
| `CACHE_TTL_SECONDS` | `120` | Cache TTL |
| `LOG_LEVEL` | `info` | Logging level |

### Analyzer Selection

The backend supports two analyzers:

1. **Flawfinder (Default)**: Specialized for C/C++ code analysis
   - Better CWE mapping for C/C++ vulnerabilities
   - Faster analysis for C code
   - Comprehensive C/C++ vulnerability detection

2. **Semgrep (Legacy)**: General-purpose static analysis
   - Multi-language support
   - Custom rule support
   - More flexible pattern matching

Switch analyzers by setting `ANALYZER=semgrep` in your environment.

## API Endpoints

### POST /scan
Scan code with suppression and pagination.

**Query Parameters:**
- `limit` (int): Maximum findings to return (default: 200)
- `offset` (int): Pagination offset (default: 0)

**Request Body:**
```json
{
  "code": "#include <stdio.h>\nint main() { printf(\"Hello\"); return 0; }",
  "filename": "test.c"
}
```

**Response:**
```json
{
  "findings": [...],
  "summary": {
    "total_findings": 5,
    "active_findings": 2,
    "suppressed_findings": 3,
    "suppression_rate": 0.6
  },
  "pagination": {
    "limit": 200,
    "offset": 0,
    "total": 5
  },
  "baseline": {...},
  "rate_limit": {...},
  "telemetry": {...}
}
```

### POST /scan/raw
Raw scan results without suppression (requires authentication).

**Headers:**
```
Authorization: Bearer your-api-token
```

### GET /health
Health check with analyzer status.

**Response:**
```json
{
  "status": "healthy",
  "analyzer": "flawfinder",
  "analyzer_available": true,
  "analyzer_version": "Flawfinder 2.0.19"
}
```

### GET /metrics
Get telemetry metrics.

### GET /alerts
Get security alerts based on thresholds.

### POST /fix
Automatically fix C code vulnerabilities using AI.

## Suppression Rules

The backend includes 24 comprehensive suppression rules to reduce false positives:

### Format String (CWE-134)
- **R1**: `printf_literal_format` - Safe literal format strings
- **R2**: `snprintf_literal_format` - Safe snprintf with explicit size
- **R3**: `format_string_safe_forward` - Safe format string forwarding

### Command Injection (CWE-78)
- **R4**: `execl_no_shell` - Safe exec without shell
- **R5**: `exec_arg_allowlist` - Safe argument validation
- **R6**: `exec_const_argv` - Constant argument arrays

### Buffer Operations (CWE-120/121/122/787)
- **R7**: `strncpy_bounds_plus_nul` - Safe strncpy with null termination
- **R8**: `strncat_space_guard` - Safe strncat with space checking
- **R9**: `scanf_width_guard` - Safe scanf with width specifiers
- **R10**: `index_bounds_guard` - Safe array indexing

### Integer Overflow (CWE-190/191)
- **R11**: `overflow_guard` - Safe addition with overflow check
- **R12**: `overflow_guard_mul` - Safe multiplication with overflow check
- **R13**: `underflow_guard` - Safe signed arithmetic

### Memory Management (CWE-401/415/416/476)
- **R14**: `free_then_null` - Safe free with null assignment
- **R15**: `null_guarded_use` - Safe null pointer usage
- **R16**: `no_post_free_use` - No use after free
- **R17**: `leak_guard` - Memory leak handled on error paths

### Path/File Operations (CWE-22/367/377)
- **R18**: `relpath_allowlist` - Safe relative path validation
- **R19**: `toctou_o_excl` - Safe file creation with O_EXCL
- **R20**: `mkstemp_safe` - Safe temporary file creation

### Sizeof Issues (CWE-467)
- **R21**: `sizeof_fixed_buffer` - Safe sizeof on arrays
- **R22**: `sizeof_deref_pointer` - Safe sizeof on dereferenced pointers

### Randomness (CWE-330)
- **R23**: `crypto_rng_present` - Cryptographic RNG present

### Context-Based
- **R24**: `context_safe` - Safe context markers

## Safety Gates

### Never-Suppress Functions
These functions are never suppressed regardless of context:
- `strcpy`, `strcat`, `gets`
- `sprintf`, `vsprintf`
- `system`, `popen`

### Strict Minimum Thresholds
Per-CWE confidence thresholds for suppression:

| CWE | Threshold | Description |
|-----|-----------|-------------|
| CWE-78 | 0.99 | Command injection (highest) |
| CWE-120/121/122 | 0.95 | Buffer overflow |
| CWE-134 | 0.95 | Format string |
| CWE-415/416 | 0.95 | Double free / Use after free |
| CWE-22/367/330/190/191/787/467 | 0.95 | Other vulnerabilities |

## CWE Mapping

Flawfinder maps to standard CWE IDs:

| Function | CWE | Description |
|----------|-----|-------------|
| `strcpy`, `strcat`, `gets` | CWE-120 | Buffer overflow |
| `sprintf`, `printf` | CWE-134 | Format string |
| `system`, `popen`, `execl*` | CWE-78 | Command injection |
| `tmpnam`, `mktemp` | CWE-377 | Insecure temp file |
| `rand`, `srand` | CWE-330 | Weak randomness |
| `memcpy`, `memmove` | CWE-787 | Out-of-bounds write |
| `open`, `fopen` | CWE-22 | Path traversal |
| `malloc`, `realloc` | CWE-190 | Integer overflow |
| `free` | CWE-415 | Double free |

## Testing

### Run Test Corpus
```bash
python tools/verify_against_api.py --base-url http://localhost:8001
```

### Test Individual Endpoints
```bash
# Health check
curl http://localhost:8001/health

# Scan code
curl -X POST http://localhost:8001/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "#include <stdio.h>\nint main() { printf(\"test\"); return 0; }", "filename": "test.c"}'

# Get metrics
curl http://localhost:8001/metrics
```

## Docker

### Build Image
```bash
docker build -t safecode-web-backend .
```

### Run Container
```bash
docker run -p 8001:8001 \
  -e SAFECODE_API_TOKEN=your-token \
  -e OPENAI_API_KEY=your-key \
  safecode-web-backend
```

### Docker Compose
```yaml
version: '3.8'
services:
  backend:
    build: .
    ports:
      - "8001:8001"
    environment:
      - SAFECODE_API_TOKEN=your-token
      - OPENAI_API_KEY=your-key
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8001/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## Monitoring

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

## Development

### Code Style
```bash
# Format code
black app/

# Lint code
flake8 app/

# Type checking
mypy app/
```

### Adding New Suppression Rules

1. Create a new rule class inheriting from `SuppressionRule`
2. Implement the `matches()` method
3. Add the rule to the `SuppressionEngine.rules` list
4. Add test cases to `tests/corpus/manifest.jsonl`

### Adding New CWE Mappings

Update the `cwe_mapping` dictionary in `flawfinder_runner.py`:

```python
self.cwe_mapping = {
    "new_function": "CWE-XXX",
    # ... existing mappings
}
```

## Troubleshooting

### Flawfinder Not Found
```bash
# Install Flawfinder
pip install flawfinder

# Verify installation
flawfinder --version
```

### Permission Denied
```bash
# Make sure Flawfinder is executable
chmod +x $(which flawfinder)
```

### Timeout Issues
Increase `FLAWFINDER_TIMEOUT` for large codebases.

### Memory Issues
Reduce `FLAWFINDER_MAX_FINDINGS` to limit memory usage.

## License

This project is licensed under the MIT License.
