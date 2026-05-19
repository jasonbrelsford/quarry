from setuptools import setup

setup(
    name="quarry-cli",
    version="0.1.0",
    description="Quarry — Supply chain security proxy CLI",
    author="Jason Brelsford",
    url="https://github.com/jasonbrelsford/quarry",
    py_modules=[],
    scripts=["quarry"],
    install_requires=["requests>=2.28.0"],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Build Tools",
    ],
)
