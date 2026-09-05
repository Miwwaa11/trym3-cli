import io
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ctf-binwalk-extract",
    version="1.0.0",
    description="File carving & embedded file extraction for CTF",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["binwalk_extract"],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
    ],
    entry_points={
        "console_scripts": [
            "binwalk-extract=binwalk_extract.cli:main",
        ],
    },
)
