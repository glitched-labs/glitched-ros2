from glob import glob
from setuptools import find_packages, setup


setup(
    name="glitched",
    version="0.1.0",
    packages=find_packages(exclude=["test", "test.*"]),
    data_files=[
        ("share/ament_index/resource_index/packages", ["resource/glitched"]),
        ("share/glitched", ["package.xml", "README.md"]),
        ("share/glitched/launch", glob("launch/*.launch.py")),
        ("share/glitched/config", glob("config/*")),
        ("share/glitched/examples", glob("examples/*.json")),
    ],
    install_requires=["setuptools"],
    tests_require=["pytest"],
    python_requires=">=3.10",
    zip_safe=True,
    maintainer="Glitched maintainers",
    maintainer_email="maintainers@example.invalid",
    description="Observational robot safety and security monitoring",
    license="Proprietary",
    entry_points={"console_scripts": [
        "glitched_monitor = glitched.monitor:main",
        "glitched_scan = glitched.scanner:main",
    ]},
)
