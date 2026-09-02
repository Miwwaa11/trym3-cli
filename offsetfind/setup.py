from setuptools import setup, find_packages

setup(
    name="offsetfind",
    version="0.1.0",
    description="Buffer Overflow Offset Finder based on pwntools.",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click",
        "rich",
        "pwntools",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "offsetfind=offsetfind.cli:main",
        ],
    },
)