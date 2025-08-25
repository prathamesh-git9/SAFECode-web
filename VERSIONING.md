# SAFECode-Web Version Management

This document explains how to manage different versions of SAFECode-Web.

## Available Versions

### Version 1.0 (v1.0)
- **Type**: Simple Flask web application
- **Features**: 
  - Basic web interface for C code analysis
  - Flawfinder SAST integration
  - GPT-powered code fixing
  - Simple and lightweight
- **Files**: `simple_web_app.py`, `simple_sast_fixer.py`
- **Usage**: Run `python simple_web_app.py`

### Version 2.0 (v2.0) - Current
- **Type**: Full FastAPI backend with advanced features
- **Features**:
  - FastAPI backend with comprehensive API
  - Flawfinder as primary analyzer (Semgrep optional)
  - 24 comprehensive false-positive suppression rules
  - Advanced telemetry and metrics
  - Rate limiting and authentication
  - Docker support
  - GitHub Actions CI/CD
- **Files**: Complete `backend/` directory structure
- **Usage**: Run `.\start_backend.bat` or `.\start_backend.ps1`

## Version Management Commands

### List All Versions
```bash
# PowerShell
.\version_manager.ps1 list

# Batch
.\version_manager.bat list
```

### Switch Between Versions
```bash
# Switch to Version 1.0 (Simple Flask app)
.\version_manager.bat switch v1.0

# Switch to Version 2.0 (FastAPI backend)
.\version_manager.bat switch v2.0

# Switch to main branch (latest development)
.\version_manager.bat switch main
```

### Create New Version
```bash
# Create a new version tag
.\version_manager.bat create v2.1 "New features added"

# PowerShell version
.\version_manager.ps1 create v2.1 "New features added"
```

## Git Commands (Alternative)

You can also use Git directly:

```bash
# List all tags
git tag --sort=-version:refname

# Switch to specific version
git checkout v1.0
git checkout v2.0
git checkout main

# Create new version
git tag -a v2.1 -m "Version 2.1: New features"
git push origin v2.1  # Push tag to remote
```

## Version Comparison

| Feature | v1.0 | v2.0 |
|---------|------|------|
| **Architecture** | Simple Flask app | Full FastAPI backend |
| **SAST Tool** | Flawfinder | Flawfinder (primary), Semgrep (optional) |
| **Suppression Rules** | Basic | 24 comprehensive rules |
| **API Endpoints** | Web interface only | RESTful API with multiple endpoints |
| **Authentication** | None | Bearer token + rate limiting |
| **Telemetry** | None | Advanced metrics and alerts |
| **Docker** | No | Yes |
| **CI/CD** | No | GitHub Actions |
| **Deployment** | Local only | Production-ready |

## Starting Applications

### Version 1.0
```bash
# After switching to v1.0
python simple_web_app.py
```
- Access at: http://localhost:5000

### Version 2.0
```bash
# After switching to v2.0 or main
.\start_backend.bat
# or
.\start_backend.ps1
```
- Backend API: http://localhost:8001
- Health Check: http://localhost:8001/health
- API Docs: http://localhost:8001/docs
- Metrics: http://localhost:8001/metrics

## Development Workflow

1. **Start with main branch** (latest development)
2. **Make changes** and test
3. **Create new version** when ready: `.\version_manager.bat create v2.1 "Description"`
4. **Test the new version**: `.\version_manager.bat switch v2.1`
5. **Push to remote** when satisfied: `git push origin v2.1`

## Important Notes

- **Don't push to main** until you're ready for a new version
- **Always test** after switching versions
- **Create tags** for important milestones
- **Use descriptive messages** when creating versions
- **Backup important changes** before switching versions

## Troubleshooting

### Detached HEAD State
When switching to a tag, you'll be in "detached HEAD" state. This is normal and expected.

### Uncommitted Changes
If you have uncommitted changes, commit or stash them before switching versions:
```bash
git add .
git commit -m "Save changes before switching"
# or
git stash
```

### Missing Files
If files seem to disappear after switching, check that you're in the right version:
```bash
git status
git log --oneline -1
```
