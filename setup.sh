#!/bin/bash
# Simple setup script for hackathon demo

echo "🛡️  Setting up AI-Powered Security Agent..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required. Please install Python 3.11+"
    exit 1
fi

echo "✅ Python found: $(python3 --version)"

# Create virtual environment for clean installation
echo "📦 Creating virtual environment..."
python3 -m venv .venv

echo "📦 Installing dependencies..."
.venv/bin/pip install \
    httpx>=0.25.0 \
    pyjwt>=2.8.0 \
    pydantic>=2.4.0 \
    typer>=0.9.0 \
    rich>=13.6.0 \
    jinja2>=3.1.0 \
    tldextract>=5.0.0 \
    python-dotenv>=1.0.0 \
    pyyaml>=6.0.1 \
    gitpython>=3.1.37 \
    aiofiles>=23.2.1 \
    asyncio-throttle>=1.0.2

echo "✅ Dependencies installed!"

# Check if Ollama is available
if command -v ollama &> /dev/null; then
    echo "✅ Ollama found: $(ollama --version 2>/dev/null || echo 'installed')"
    
    # Check if llama3 model is available
    if ollama list | grep -q llama3; then
        echo "✅ llama3 model ready"
    else
        echo "📥 Pulling llama3 model (this may take a few minutes)..."
        ollama pull llama3
    fi
else
    echo "⚠️  Ollama not found. Installing..."
    echo "Please install Ollama:"
    echo "  macOS: brew install ollama"
    echo "  Linux: curl -fsSL https://ollama.ai/install.sh | sh"
    echo ""
    echo "Then run: ollama pull llama3"
fi

echo ""
echo "🚀 Setup complete! Test with:"
echo "  source .venv/bin/activate"
echo "  python3 -m secagent.cli --help"
echo ""
echo "Example usage:"
echo "  source .venv/bin/activate"
echo "  python3 -m secagent.cli --repo . --base-url https://api.example.com"
