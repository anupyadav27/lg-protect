#!/bin/bash
# setup_env.sh - Complete environment setup script

echo "🚀 Setting up Kubernetes Security Scanner Environment..."

# Navigate to project directory
cd /Users/apple/Desktop/github/prowler/providers/kubernetes

# Check if virtual environment already exists
if [ -d "venv" ]; then
    echo "⚠️  Virtual environment already exists. Removing old one..."
    rm -rf venv
fi

# Create virtual environment
echo "📦 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "�� Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "⬆️  Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "📥 Installing dependencies..."
pip install -r requirements.txt

# Verify installation
echo "✅ Verifying installation..."
python -c "import kubernetes; print(f'✅ kubernetes version: {kubernetes.__version__}')"
python -c "import yaml; print('✅ PyYAML installed successfully')"

echo "🎉 Environment setup complete!"
echo ""
echo "To activate the environment in the future, run:"
echo "source venv/bin/activate"
echo ""
echo "To test the dynamic loading, run:"
echo "python test.py"
