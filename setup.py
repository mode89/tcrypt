import setuptools

setuptools.setup(
    name="tcrypt",
    version=f"0.0.1",
    author="Andrey Krainyak",
    author_email="mode.andrew@gmail.com",
    description="Handling secrets in terminal",
    packages=setuptools.find_packages(),
    install_requires=[
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "tcrypt=tcrypt.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8"
)
