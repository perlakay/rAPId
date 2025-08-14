# 🛡️ AI-Powered API Security Agent

**Local-first codebase+API security testing with AI-powered analysis**

A comprehensive security agent that combines static code analysis with active API testing, enhanced by local AI (Ollama) for intelligent vulnerability analysis and remediation guidance.

## 🚀 Features

- **🔍 Multi-Framework Discovery**: Automatically detects API endpoints from OpenAPI specs, GraphQL schemas, and popular frameworks (Node.js, Python)
- **🧪 Active Security Testing**: Tests for BOLA/IDOR, authentication bypass, and JWT manipulation vulnerabilities  
- **🤖 AI-Powered Analysis**: Uses local Ollama LLM for intelligent vulnerability pattern analysis and remediation recommendations
- **📊 Beautiful Reports**: Generates comprehensive HTML and Markdown reports with AI insights
- **🔒 Privacy-First**: Everything runs locally - no data leaves your machine
- **⚡ Safety Controls**: Built-in consent banners, safe mode, and rate limiting

## 🛠️ Installation

### Prerequisites

1. **Python 3.11+**
2. **Ollama** (for AI features)

### ⚡ Quick Setup (Hackathon Mode)

```bash
# 1. Clone the repository
git clone <your-repo-url>
cd rAPId

# 2. Run the setup script (installs everything)
./setup.sh

# 3. Start testing!
python3 -m secagent.cli --help
```

### 🔧 Manual Setup (Development)

```bash
# 1. Clone and enter directory
git clone <your-repo-url>
cd rAPId

# 2. Create virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -e .

# 4. Install Ollama
# macOS: brew install ollama
# Linux: curl -fsSL https://ollama.ai/install.sh | sh

# 5. Pull AI model and start service
ollama pull llama3
ollama serve
```

### Optional Dependencies

```bash
# For enhanced static analysis
pip install semgrep
```

## 🎯 Quick Start

### Basic Usage

```bash
# Test a local repository against a live API
secagent --repo ./my-app --base-url https://api.myapp.com

# Test with authentication
secagent --repo ./my-app --base-url https://api.myapp.com \
  --auth-header "Authorization: Bearer your-token-here"

# Generate only HTML report
secagent --repo ./my-app --base-url https://api.myapp.com --report html
```

### Advanced Usage

```bash
# Test with custom settings
secagent --repo ./my-app --base-url https://api.myapp.com \
  --concurrency 5 \
  --delay-ms 500 \
  --timeout-ms 10000 \
  --unsafe \
  --verbose

# Test with explicit OpenAPI spec
secagent --repo ./my-app --base-url https://api.myapp.com \
  --openapi ./docs/openapi.yaml

# Test GraphQL API
secagent --repo ./my-app --base-url https://api.myapp.com \
  --graphql-endpoint /graphql
```

## 🧠 AI Features

The security agent uses **Ollama** (local LLM) to provide:

- **Executive Summaries**: AI-generated overview of security posture
- **Vulnerability Pattern Analysis**: Identifies systemic security weaknesses
- **Smart Remediation**: Context-aware fix recommendations
- **Risk Prioritization**: AI-enhanced risk scoring

### Supported AI Models

```bash
# Recommended models
ollama pull llama3        # Best overall performance
ollama pull mistral       # Fast and efficient
ollama pull codellama     # Code-focused analysis

# Use specific model
secagent --repo ./app --base-url https://api.app.com --ollama-model mistral
```

## 🔧 Configuration

### Environment Variables

Create a `.env` file in your project:

```env
# API Configuration
BASE_URL=https://api.myapp.com
API_TOKEN=your-api-token-here

# Ollama Configuration  
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# Security Settings
CONCURRENCY=3
DELAY_MS=200
TIMEOUT_MS=8000
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--repo` | Repository path or Git URL | Required |
| `--base-url` | API base URL to test | Required |
| `--auth-header` | Authorization header | None |
| `--unsafe` | Enable mutating requests | False |
| `--concurrency` | Concurrent requests | 3 |
| `--delay-ms` | Delay between requests | 200ms |
| `--timeout-ms` | Request timeout | 8000ms |
| `--report` | Report format (md/html/both) | both |
| `--ollama-model` | Ollama model name | llama3 |
| `--verbose` | Verbose output | False |

## 🧪 Security Tests

### BOLA/IDOR Testing
- Detects broken object level authorization
- Tests ID parameter manipulation
- Identifies unauthorized data access

### Authentication Bypass
- Tests missing authentication
- Validates auth header requirements
- Detects weak authentication controls

### JWT Manipulation
- Tests algorithm confusion attacks
- Validates JWT signature verification
- Detects privilege escalation via claims

## 📊 Reports

The agent generates comprehensive reports with:

- **🤖 AI Executive Summary**
- **📈 Risk Assessment Dashboard** 
- **🔍 Vulnerability Details with AI Remediation**
- **📋 Complete Endpoint Inventory**
- **🛠️ Technical Implementation Details**

### Sample Report Structure

```
runs/20240813_220000/
├── repo_info.json          # Repository metadata
├── static.json             # Static analysis results  
├── plan.jsonl              # Test execution plan
├── tests.jsonl             # Test results
├── security.db             # SQLite database
├── report.md               # Markdown report
├── report.html             # HTML report
└── artifacts/              # Additional evidence
```

## 🛡️ Safety & Ethics

### Built-in Safety Controls

- **Consent Banner**: Requires explicit permission before testing
- **Safe Mode**: Mutating requests disabled by default
- **Rate Limiting**: Respects target API limits
- **Data Masking**: Sensitive information masked in reports

### Responsible Usage

⚠️ **IMPORTANT**: Only test APIs and applications you own or have explicit permission to test.

- This tool performs active security testing
- Testing may trigger security alerts
- Always follow responsible disclosure practices
- Respect rate limits and terms of service

## 🔍 Supported Frameworks

### Static Analysis Support

**Node.js/JavaScript:**
- Express.js
- NestJS  
- Fastify
- Koa

**Python:**
- FastAPI
- Flask
- Django + DRF

**API Specifications:**
- OpenAPI 3.x / Swagger 2.x
- GraphQL schemas

## 🚨 Troubleshooting

### Common Issues

**Ollama Connection Failed**
```bash
# Check if Ollama is running
ollama list

# Start Ollama service
ollama serve

# Pull required model
ollama pull llama3
```

**No Endpoints Discovered**
```bash
# Specify OpenAPI spec explicitly
secagent --repo ./app --base-url https://api.app.com --openapi ./docs/api.yaml

# Enable verbose mode for debugging
secagent --repo ./app --base-url https://api.app.com --verbose
```

**Permission Errors**
```bash
# Ensure you have permission to test the target API
# Check authentication headers
secagent --repo ./app --base-url https://api.app.com --auth-header "Authorization: Bearer TOKEN"
```

## 🤝 Contributing

This is a hackathon project! Contributions welcome:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🙏 Acknowledgments

- **Ollama** for local AI capabilities
- **OWASP** for security testing methodologies
- **OpenAPI Initiative** for API specification standards

---

**⚡ Built for hackathons, designed for security professionals, powered by local AI.**
