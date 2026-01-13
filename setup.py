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
    version="5.0.0",
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
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Text Processing :: Filters",
    ],
    python_requires=">=3.10",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=9.0.2",
            "pytest-cov>=7.0.0",
            "ruff>=0.14.11",
            "mypy>=1.19.1",
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
