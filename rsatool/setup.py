import io
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ctf-rsatool",
    version="1.0.0",
    description="RSA Attack Helper for CTF crypto",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
        "sympy>=1.10",
    ],
    entry_points={
        "console_scripts": [
            "rsatool=rsatool.cli:main",
        ],
    },
)