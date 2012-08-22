from setuptools import setup

setup(
    # Do not use the option 'include_datafiles', or 'include_packagefiles'
    # until we remove the key we are using to sign packages
    name='siptest',
    version='1.0',
    author='Simon P. Ditner',
    description='SIP Registration Test',
    packages=[
        'siptest',
    ],
    package_data={'siptest': ['test.wav']},
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'siptest = siptest.canwecall:main',
            'detectsipalg = siptest.detectsipalg:main',
        ],
    },
)
