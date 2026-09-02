import io
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ctf-autodecode",
    version="1.0.0",
    description="Multi-Cipher Auto-Decoder for CTF",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
    ],
    entry_points={
        "console_scripts": [
            "autodecode=autodecode.cli:main",
        ],
    },
    package_data={"autodecode": ["data/*.txt"]},
)
