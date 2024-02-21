from setuptools import setup

exec(open('client_encryption/version.py').read())

setup(name='mastercard-client-encryption',
      python_requires='>=3.8',
      version=__version__,
      description='Mastercard Client encryption.',
      long_description='Library for Mastercard API compliant payload encryption/decryption.',
      author='Mastercard',
      url='https://github.com/Mastercard/client-encryption-python',
      license='MIT',
      packages=['client_encryption'],
      classifiers=[
          'Development Status :: 5 - Production/Stable',
          'Intended Audience :: Developers',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Topic :: Software Development :: Libraries :: Python Modules'
      ],
      tests_require=['coverage'],
      install_requires=['pycryptodome>=3.8.1', 'setuptools>=69.1.0', 'cryptography>=42.0.0' ]
      )
