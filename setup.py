from setuptools import find_packages, setup


setup(
    name="clawdbot",
    version="0.1.0",
    description="Minimal ClawdBot runtime and security tooling package",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    install_requires=[
        "PyYAML>=6.0",
        "click>=8.1",
        "tabulate>=0.9",
        "requests>=2.32",
        "cryptography>=44.0",
        "boto3>=1.35",
        "jinja2>=3.1",  # FIX: C5-finding-3
        "networkx>=3.3",  # FIX: C5-finding-3
        "psutil>=6.0",  # FIX: C5-finding-3
    ],
    entry_points={
        "console_scripts": [
            "openclaw-cli=clawdbot.openclaw_cli:main",
        ]
    },
)