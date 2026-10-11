import os

from setuptools import find_packages, setup

HERE = os.path.dirname(os.path.abspath(__file__))
README = os.path.join(HERE, "README.md")

setup(
    name="vaultix-sdk",
    version="2.0.0",
    author="Vaultix",
    author_email="support@vaultix.cc",
    description="Python client library for the Vaultix API, with end-to-end encrypted downloads and signed responses",
    long_description=open(README, encoding="utf-8").read() if os.path.exists(README) else "",
    long_description_content_type="text/markdown",
    url="https://github.com/Vaultix-cc/Vaultix",
    packages=find_packages(exclude=["tests", "tests.*", "examples"]),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=[
        # X25519, Ed25519, AES-256-GCM, HKDF, PBKDF2 and X.509 parsing. HTTP uses
        # the standard library (urllib).
        "cryptography>=3.4",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
        ],
    },
)
