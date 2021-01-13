import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


setuptools.setup(
    name='jwt-postgresql-proxy',
    version='0.0.2',
    author='Department for International Trade',
    author_email='webops@digital.trade.gov.uk',
    description='Stateless JWT authentication in front of PostgreSQL',
    long_description=long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/uktrade/jwt-postgresql-proxy',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
    python_requires='>=3.8.0',
    install_requires=[
        'cryptography>=3.3.1',
        'gevent>=20.12.1',
    ],
    py_modules=[
        'jwt_postgresql_proxy',
    ],
    entry_points={
        'console_scripts': [
            'jwt-postgresql-proxy=jwt_postgresql_proxy:main'
        ],
    },
)
