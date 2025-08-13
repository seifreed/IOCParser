#!/usr/bin/env python3


from setuptools import find_packages, setup


# Read the README file
def read_readme():
    with open("README.md", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="iocparser-tool",
    version="1.0.1",
    author="Marc Rivero",
    author_email="",
    description="A tool for extracting Indicators of Compromise from security reports",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/seifreed/iocparser",
    project_urls={
        "Bug Tracker": "https://github.com/seifreed/iocparser/issues",
        "Documentation": "https://github.com/seifreed/iocparser#readme",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Text Processing :: Filters",
    ],
    python_requires=">=3.6",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
    },
    entry_points={
        "console_scripts": [
            "iocparser=iocparser.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "iocparser": [
            "modules/data/*.json",
        ],
    },
    keywords="security, ioc, malware, threat-intelligence, pdf, html, parser",
    license="MIT",
    zip_safe=False,
)
