from setuptools import setup, find_packages

setup(
    name="pades-lta-renewer",
    version="0.1.0",
    description="Motor de preservación y renovación de sellos de tiempo PAdES-B-LTA",
    author="Gabriel Serrano Rojas, Josué Torres Sibaja",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.10",
    install_requires=[
        "asn1crypto>=1.5.1",
        "requests>=2.28.0",
        "cryptography>=3.4.0",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
)
