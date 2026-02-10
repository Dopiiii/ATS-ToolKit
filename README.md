# OSINT Platform

Enterprise intelligence gathering and analysis platform.

## Features (Phase 1)

- **Authentication**: JWT-based auth with refresh tokens
- **User Management**: RBAC with admin, analyst, viewer roles
- **API Keys**: Scoped API keys for programmatic access
- **Audit Logging**: Complete audit trail of all actions

## Quick Start

### Prerequisites

- Python 3.11+
- Docker and Docker Compose
- Poetry (recommended) or pip

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd osint-platform

# Copy environment file
cp .env.example .env

# Edit .env with your settings (especially SECRET_KEY)
```

### 2. Start Database Services

```bash
docker-compose up -d postgres redis
```

### 3. Install Dependencies

```bash
# Using pip
pip install -e ".[dev]"

# Or using poetry
poetry install --with dev
```

### 4. Run Database Migrations

```bash
alembic upgrade head
```

### 5. Start the API Server

```bash
# Development mode (with auto-reload)
uvicorn src.main:app --reload

# Or using the CLI
python -m src.main
```

### 6. Access the API

- API Documentation: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
- Health Check: http://localhost:8000/api/v1/health

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login and get tokens |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout (audit only) |
| GET | `/api/v1/auth/me` | Get current user |
| POST | `/api/v1/auth/change-password` | Change password |

### Users (Admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users` | List all users |
| POST | `/api/v1/users` | Create user |
| GET | `/api/v1/users/{id}` | Get user |
| PATCH | `/api/v1/users/{id}` | Update user |
| DELETE | `/api/v1/users/{id}` | Delete user |

### API Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/users/me/api-keys` | List my API keys |
| POST | `/api/v1/users/me/api-keys` | Create API key |
| DELETE | `/api/v1/users/me/api-keys/{id}` | Delete API key |

## Authentication

The API supports two authentication methods:

### 1. JWT Bearer Token

```bash
# Login to get tokens
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "YourPassword123"}'

# Use the access token
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"
```

### 2. API Key

```bash
# Create an API key (requires authentication first)
curl -X POST http://localhost:8000/api/v1/users/me/api-keys \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{"name": "My API Key", "scopes": ["collections:read", "entities:read"]}'

# Use the API key
curl http://localhost:8000/api/v1/auth/me \
  -H "X-API-Key: osint_<your_key>"
```

## Running Tests

```bash
# Create test database
docker exec -it osint_postgres psql -U osint -c "CREATE DATABASE osint_test_db;"

# Run tests
pytest

# With coverage
pytest --cov=src --cov-report=html
```

## Project Structure

```
osint-platform/
├── src/
│   ├── api/              # API routes
│   │   └── v1/
│   ├── core/             # Core infrastructure
│   │   ├── database.py   # SQLAlchemy setup
│   │   ├── security.py   # JWT & hashing
│   │   ├── logging.py    # Structlog
│   │   └── exceptions.py # Custom exceptions
│   ├── models/           # SQLAlchemy models
│   ├── schemas/          # Pydantic schemas
│   ├── services/         # Business logic
│   ├── config.py         # Configuration
│   └── main.py           # FastAPI app
├── migrations/           # Alembic migrations
├── tests/                # Test suite
├── docker-compose.yml    # Docker services
├── pyproject.toml        # Dependencies
└── README.md
```

## Environment Variables

See `.env.example` for all available configuration options.

Key variables:
- `SECRET_KEY`: JWT signing key (required, min 32 chars)
- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `DEBUG`: Enable debug mode

## Next Phases

This is Phase 1 of the OSINT Platform. Upcoming phases:

- **Phase 2**: Data Collection Engine (10+ collectors)
- **Phase 3**: Storage & Search (Elasticsearch, Neo4j)
- **Phase 4**: React Frontend
- **Phase 5**: Analysis & ML
- **Phase 6**: Automation & Workflows
- **Phase 7**: Reporting
- **Phase 8**: Enterprise Features

## License

MIT
