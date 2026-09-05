import io
import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ctf-z3-solver",
    version="1.0.0",
    description="Z3 constraint solver helper for CTF reversing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["z3solver"],
    python_requires=">=3.9",
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
    ],
    extras_require={
        "solve": ["z3-solver>=4.8"],
    },
    entry_points={
        "console_scripts": [
            "z3-solver=z3solver.cli:main",
        ],
    },
)
