from setuptools import setup

setup(
    name='simpleSecureSocks',
    packages=['simpleSecureSocks'],
    include_package_data=True,
    install_requires=[
        'flask',
        'numpy',
        'ormsgpack',
        'cryptography'
    ],
)