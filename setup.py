# BRS-GPT: AI-Powered Cybersecurity Analysis Tool
# Company: EasyProTech LLC (www.easypro.tech)
# Dev: Brabus
# Date: 2025-09-16 00:28:00 UTC
# Status: Modified
# Telegram: https://t.me/easyprotech

from setuptools import setup, find_packages

try:
    with open("README.md", "r", encoding="utf-8") as fh:
        long_description = fh.read()
except FileNotFoundError:
    long_description = "BRS-GPT: AI-Powered Cybersecurity Analysis Tool"

try:
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]
except FileNotFoundError:
    requirements = [
        "openai>=1.0.0", "aiohttp>=3.8.0", "asyncio-throttle>=1.0.2", 
        "dnspython>=2.3.0", "requests>=2.28.0", "beautifulsoup4>=4.11.0",
        "jinja2>=3.1.0", "rich>=13.0.0", "pydantic>=2.0.0", "toml>=0.10.2"
    ]

# Read version from file without importing the module
try:
    with open("brsgpt/version.py", "r") as f:
        for line in f:
            if line.startswith("VERSION"):
                VERSION = line.split('=')[1].strip().strip('"').strip("'")
                break
        else:
            VERSION = "0.0.1"
except FileNotFoundError:
    VERSION = "0.0.1"

setup(
    name="brs-gpt",
    version=VERSION,
    author="Brabus",
    author_email="",
    description="AI-Powered Cybersecurity Analysis Tool - Autonomous reconnaissance and XSS scanning with OpenAI intelligence",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/EPTLLC/brs-gpt",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "brs-gpt=brsgpt.cli.main:main",
        ],
    },
    keywords="cybersecurity ai openai xss reconnaissance pentesting security-analysis",
    project_urls={
    "Bug Reports": "https://github.com/EPTLLC/brs-gpt/issues",
    "Source": "https://github.com/EPTLLC/brs-gpt",
        "Company": "https://www.easypro.tech",
        "Telegram": "https://t.me/easyprotech",
    },
)
