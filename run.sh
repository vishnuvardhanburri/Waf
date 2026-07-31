#!/bin/bash

# Check for Python 3.8+
if ! command -v python3 &> /dev/null
then
    echo "Python 3 could not be found. Please install Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if (( $(echo "$PYTHON_VERSION < 3.8" | bc -l) )); then
    echo "Python version must be 3.8+. Current version is $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

# Create logs directory
if [ ! -d "logs" ]; then
    mkdir logs
fi

# Run the app
echo "Starting PyWAF Demo Application..."
python app.py
