#!/usr/bin/env python3
"""
Build script for IOCParser PyPI package
"""

import os
import subprocess
import sys
from pathlib import Path


def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")

    result = subprocess.run(cmd, check=False, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False

    print(f"Success: {result.stdout}")
    return True

def main():
    """Main build function"""
    print("Building IOCParser package for PyPI...")

    # Clean previous builds
    print("\n1. Cleaning previous builds...")
    for path in ["build/", "dist/", "*.egg-info/"]:
        if os.path.exists(path):
            subprocess.run(["rm", "-rf", path], check=False)

    # Check if we're in the right directory
    if not os.path.exists("setup.py"):
        print("Error: setup.py not found. Make sure you're in the project root.")
        sys.exit(1)

    # Build the package
    print("\n2. Building package...")
    if not run_command([sys.executable, "setup.py", "sdist", "bdist_wheel"], "Building source distribution and wheel"):
        sys.exit(1)

    # Check the built package
    print("\n3. Checking built package...")
    if not run_command([sys.executable, "-m", "twine", "check", "dist/*"], "Checking package with twine"):
        print("Note: Install twine with 'pip install twine' to check packages")

    print("\n4. Package built successfully!")
    print("Files created in dist/ directory:")

    dist_dir = Path("dist")
    if dist_dir.exists():
        for file in dist_dir.iterdir():
            print(f"  - {file.name}")

    print("\nTo upload to PyPI:")
    print("1. Test upload to TestPyPI:")
    print("   twine upload --repository testpypi dist/*")
    print("\n2. Upload to PyPI:")
    print("   twine upload dist/*")

    print("\nTo install locally for testing:")
    print("   pip install dist/*.whl")

if __name__ == "__main__":
    main()
