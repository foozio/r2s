#!/bin/bash
# React2Shell Vulnerability Checker - Ubuntu/Linux Installation Script

echo "Installing React2Shell Vulnerability Checker for Ubuntu/Linux..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is not installed. Installing..."
    sudo apt update
    sudo apt install -y python3 python3-pip
else
    echo "Python 3 is already installed."
fi

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "pip is not installed. Installing..."
    sudo apt install -y python3-pip
else
    echo "pip is already installed."
fi

# Install dependencies
echo "Installing required dependencies..."
pip3 install -r requirements.txt

# Make the script executable
chmod +x react2shell_checker_linux.py

echo "Installation completed!"
echo ""
echo "To run the checker, use:"
echo "  python3 react2shell_checker_linux.py --path /path/to/your/project"
echo "  python3 react2shell_checker_linux.py --url https://your-site.example"