# Copyright (C) 2017-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - https://cuckoosandbox.org/.
# See the file 'docs/LICENSE' for copying permission.

import setuptools

setuptools.setup(
    name="egghatch",
    version="0.2.3",
    author="Jurriaan Bremer",
    author_email="jbr@cuckoo.sh",
    packages=[
        "egghatch",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Framework :: Pytest",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Natural Language :: English",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.8",
        "Topic :: Security",
    ],
    url="https://cuckoosandbox.org/",
    license="GPLv3",
    description="Cuckoo Sandbox Shellcode Identification & Formatting",
    long_description=str(open("README.rst", "rb").read()),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "egghatch = egghatch.main:main",
        ],
    },
    install_requires=[
    ],
    extras_require={
        ":sys_platform == 'win32'": [
            "capstone-windows==3.0.4",
        ],
        ":sys_platform == 'darwin'": [
            "capstone==4.0.2",
        ],
        ":sys_platform == 'linux2'": [
            "capstone==4.0.2",
        ],
    },
)
