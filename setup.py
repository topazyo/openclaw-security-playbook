from setuptools import find_packages, setup


setup(
    name="clawdbot",
    version="0.1.0",
    description="Minimal ClawdBot runtime and security tooling package",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    install_requires=["PyYAML>=6.0"],
)