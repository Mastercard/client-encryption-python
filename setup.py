from setuptools import setup

exec(open('client_encryption/version.py').read())

setup(name='mastercard-client-encryption',
      python_requires='>=3.5.4',
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
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Topic :: Software Development :: Libraries :: Python Modules'
      ],
      tests_require=['coverage'],
      install_requires=['pycryptodome>=3.8.1', 'pyOpenSSL>=19.0.0', 'setuptools>=39.0.1']
      )
