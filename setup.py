#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="iocparser",
    version="1.0.0",
    author="Marc Rivero",
    author_email="",
    description="A tool for extracting Indicators of Compromise from security reports",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/seifreed/iocparser",
    packages=find_packages(),
    install_requires=[
        "colorama",
        "python-magic",
        "requests",
        "tqdm",
        "pdfminer.six",
        "beautifulsoup4",
        "lxml"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security"
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "iocparser=iocparser.main:main",
        ],
    },
    include_package_data=True,
) 