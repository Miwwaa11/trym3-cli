import io
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ctf-netcat-recon",
    version="1.0.0",
    description="Network reconnaissance: port scan & banner grab",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["netcat_recon"],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
    ],
    entry_points={
        "console_scripts": [
            "netcat-recon=netcat_recon.cli:main",
        ],
    },
)
