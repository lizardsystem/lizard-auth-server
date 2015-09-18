from setuptools import setup

version = '0.8'

long_description = '\n\n'.join([
    open('README.rst').read(),
    open('CREDITS.rst').read(),
    open('CHANGES.rst').read(),
    ])

install_requires = [
    'Django >= 1.6, < 1.7',
    'django-extensions',
    'django-nose',
    'south',
    'requests',
    'itsdangerous',
    'pytz',
    'factory_boy >= 1.3.0',
    ],

tests_require = [
    'nose',
    'coverage',
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
