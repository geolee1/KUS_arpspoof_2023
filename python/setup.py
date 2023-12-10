from setuptools import setup

setup(
    name='arpspoof',
    version='1.0.0',
    packages=['arpspoof'],
    install_requires=[
        'scapy',
    ],
    entry_points={
        'console_scripts': [
            'arpspoof=arpspoof.main:main',
        ],
    },
)