from setuptools import setup, find_packages

with open("README.md", "r") as f:
    LONG_DESCRIPTION = f.read()

VERSION = "1.2.0"
DESCRIPTION = "Web fuzzer finding differences based on response diffing"

setup(
    name="Diffuzz",
    version=VERSION,
    author="William",
    author_email="william.kristof@gmail.com",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=["requests","httpdiff","httpinsert"],
    classifiers=[],
    scripts=["diffuzz/diffuzz"]

)
