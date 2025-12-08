#!/usr/bin/env python3
# React2Shell Vulnerability Checker - Cross-Platform Installation Script

import os
import sys
import platform
import subprocess

def install_dependencies():
    """Install required dependencies using pip"""
    print("Installing required dependencies...")
    
    try:
        # Try to install using pip
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("Dependencies installed successfully!")
    except subprocess.CalledProcessError:
        print("Error: Failed to install dependencies. Please install manually using 'pip install -r requirements.txt'")
        sys.exit(1)

def main():
    print(f"Installing React2Shell Vulnerability Checker for {platform.system()}...")
    
    # Check if Python is available
    if sys.version_info < (3, 6):
        print("Error: Python 3.6 or higher is required.")
        sys.exit(1)
    
    # Install dependencies
    install_dependencies()
    
    print("Installation completed!")
    print("")
    
    if platform.system() == "Windows":
        print("To run the checker, use:")
        print("  python react2shell_checker.py --path C:\\path\\to\\your\\project")
        print("  python react2shell_checker.py --url https://your-site.example")
    else:
        print("To run the checker, use:")
        print("  python3 react2shell_checker.py --path /path/to/your/project")
        print("  python3 react2shell_checker.py --url https://your-site.example")

if __name__ == "__main__":
    main()