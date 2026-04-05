import os

from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='passerelle-goodflag',
    version='1.3.0',
    description='Connecteur Passerelle pour la signature électronique Goodflag',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Entr\'ouvert / Intégrateur Publik',
    author_email='info@entrouvert.com',
    url='https://git.entrouvert.org/',
    license='AGPLv3+',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'passerelle',
    ],
    entry_points={
        'passerelle.connectors': [
            'goodflag = passerelle_goodflag',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
    ],
    zip_safe=False,
)
