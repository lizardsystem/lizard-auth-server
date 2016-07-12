from setuptools import setup

version = '2.1.dev0'

long_description = '\n\n'.join([
    open('README.rst').read(),
    open('CREDITS.rst').read(),
    open('CHANGES.rst').read(),
    ])

install_requires = [
    'Django >= 1.9',
    'django-appconf',
    'django-extensions',
    'django-nose',
    'django-tls',
    'itsdangerous',
    'pyjwt',
    'pytz',
    'requests',
    'six',
    'translations',
    ],

tests_require = [
    'coverage',
    'factory_boy >= 2.4.0',
    'fake-factory',
    'mock',
    'nose',
    ]

setup(name='lizard-auth-server',
      version=version,
      description="A single sign-on server for centralized authentication",
      long_description=long_description,
      # Get strings from http://www.python.org/pypi?%3Aaction=list_classifiers
      classifiers=['Programming Language :: Python',
                   'Framework :: Django',
                   ],
      keywords=[],
      author='Erik-Jan Vos, Remco Gerlich',
      author_email='remco.gerlich@nelen-schuurmans.nl',
      url='http://www.nelen-schuurmans.nl/',
      license='MIT',
      packages=['lizard_auth_server'],
      include_package_data=True,
      zip_safe=False,
      install_requires=install_requires,
      tests_require=tests_require,
      extras_require={'test': tests_require},
      entry_points={
          'console_scripts': [
          ]},
      )
