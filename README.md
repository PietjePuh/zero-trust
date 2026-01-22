# Zero Trust Platform

AI-Powered Zero Trust Security Infrastructure built with FastAPI, Weaviate, and Claude.

## Overview

A production-grade zero trust security platform that implements:

- **Threat Intelligence RAG** - Semantic search across CVEs, MITRE ATT&CK, and security advisories
- **Policy Engine** - ABAC-style policy evaluation with LLM-assisted reasoning
- **Risk Assessment** - Real-time risk scoring combining multiple signals
- **Anomaly Detection** - Behavioral analysis and pattern detection
- **Complete Audit Trail** - Every decision logged and explainable

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Zero Trust Platform                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   FastAPI    │  │   Policy     │  │   Threat Intel       │  │
│  │   Gateway    │──│   Engine     │──│   RAG System         │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Identity   │  │   Anomaly    │  │   Vector Store       │  │
│  │   Verifier   │  │   Detector   │  │   (Weaviate)         │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         │                │                      │               │
│         └────────────────┴──────────────────────┘               │
│                          │                                      │
│              ┌───────────┴───────────┐                         │
│              │   PostgreSQL + Redis  │                         │
│              └───────────────────────┘                         │
└─────────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Component | Technology |
|-----------|------------|
| API Framework | FastAPI (async, typed) |
| Vector Store | Weaviate (hybrid search) |
| Database | PostgreSQL + SQLAlchemy 2.0 |
| Cache | Redis |
| LLM | Anthropic Claude |
| Auth | JWT (python-jose) |
| Validation | Pydantic v2 |
| Logging | structlog |

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Anthropic API key (optional, for AI features)

### Development Setup

1. **Clone and setup environment**

```bash
git clone <repository-url>
cd zero-trust

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows

# Install dependencies
pip install -e ".[dev]"
```

2. **Configure environment**

```bash
cp .env.example .env
# Edit .env with your settings (especially ANTHROPIC_API_KEY for AI features)
```

3. **Start infrastructure**

```bash
docker-compose up -d postgres weaviate redis t2v-transformers
```

4. **Run the API**

```bash
# Development mode with auto-reload
uvicorn zero_trust.main:app --reload --port 8000

# Or use the CLI
zero-trust
```

5. **Access the API**

- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/api/v1/health

### Docker Deployment

```bash
# Build and run everything
docker-compose up -d

# View logs
docker-compose logs -f api
```

## API Endpoints

### Health & Status
- `GET /api/v1/health` - Liveness probe
- `GET /api/v1/ready` - Readiness probe
- `GET /api/v1/health/detailed` - Detailed health info

### Authentication
- `POST /api/v1/auth/login` - Authenticate and get tokens
- `POST /api/v1/auth/refresh` - Refresh access token
- `GET /api/v1/auth/me` - Get current user info
- `POST /api/v1/auth/verify` - Zero-trust verification

### Policy Engine
- `GET /api/v1/policy/` - List policies
- `POST /api/v1/policy/` - Create policy
- `POST /api/v1/policy/evaluate` - Evaluate policies
- `POST /api/v1/policy/from-natural-language` - Create policy from natural language

### Threat Intelligence
- `POST /api/v1/threat-intel/query` - Search threat intelligence
- `GET /api/v1/threat-intel/cve/{cve_id}` - Get CVE details
- `GET /api/v1/threat-intel/mitre/{technique_id}` - Get MITRE technique
- `POST /api/v1/threat-intel/analyze` - AI threat analysis

### Risk Assessment
- `POST /api/v1/risk/user` - Assess user risk
- `POST /api/v1/risk/device` - Assess device risk
- `POST /api/v1/risk/request` - Assess request risk
- `GET /api/v1/risk/trend/{entity_type}/{entity_id}` - Get risk trend

## Project Structure

```
zero-trust/
├── src/zero_trust/
│   ├── api/
│   │   ├── routes/          # API endpoints
│   │   ├── middleware/      # Security, logging middleware
│   │   └── dependencies.py  # FastAPI dependencies
│   ├── core/
│   │   ├── security.py      # JWT, password hashing
│   │   └── exceptions.py    # Custom exceptions
│   ├── domain/
│   │   ├── policy/          # Policy engine
│   │   ├── threat_intel/    # Threat intelligence
│   │   └── risk/            # Risk assessment
│   ├── infrastructure/
│   │   ├── database/        # SQLAlchemy models
│   │   └── vector_store/    # Weaviate client
│   ├── config.py            # Configuration
│   └── main.py              # FastAPI app
├── tests/
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

## Configuration

Configuration is managed via environment variables. See `.env.example` for all options.

Key settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_ENV` | Environment (development/staging/production) | development |
| `DEBUG` | Enable debug mode | false |
| `DATABASE_URL` | PostgreSQL connection string | postgresql+asyncpg://... |
| `WEAVIATE_URL` | Weaviate server URL | http://localhost:8080 |
| `ANTHROPIC_API_KEY` | Claude API key | (required for AI features) |
| `SECRET_KEY` | JWT signing key | (required in production) |

## Development

### Running Tests

```bash
pytest
pytest --cov=zero_trust  # with coverage
```

### Code Quality

```bash
# Linting
ruff check src/

# Type checking
mypy src/

# Format
ruff format src/
```

### Pre-commit Hooks

```bash
pre-commit install
pre-commit run --all-files
```

## Security Considerations

- All endpoints require authentication (except health checks)
- JWT tokens with short expiration
- Passwords hashed with bcrypt
- Security headers on all responses
- Rate limiting enabled
- Audit logging for all operations
- No secrets in code or logs

## License

MIT

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request
