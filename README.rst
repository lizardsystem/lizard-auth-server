Lizard-auth-server README
==========================================


.. image:: https://travis-ci.org/lizardsystem/lizard-auth-server.svg?branch=master
    :target: https://travis-ci.org/lizardsystem/lizard-auth-server

.. image:: https://coveralls.io/repos/lizardsystem/lizard-auth-server/badge.svg?branch=master&service=github
  :target: https://coveralls.io/github/lizardsystem/lizard-auth-server?branch=master

Lizard auth server was originally build upon django-simple-sso_.

It is installed as https://sso.lizard.net, see https://github.com/nens/sso/


Workflow
---------

The workflow follows the django simple sso workflow_.


.. _django-simple-sso: http://pypi.python.org/pypi/django-simple-sso
.. _workflow: https://github.com/ojii/django-simple-sso#workflow


Updating translations
---------------------

Go to the ``lizard_auth_server`` subdirectory::

    $ cd lizard_auth_server
    $ ../python3 manage.py makemessages --all

Update the translations (for Dutch), for instance with "poedit". Then compile
the new translations::

    $ ../python3 manage.py compilemessages

Note: this also fetches af/vi/zh, but we don't translate into those languages
currently. They're ignored in the ``.gitignore`` file.


Development with docker
-----------------------

The short version::

    $ docker-compose build
    $ docker-compose run web make install
    $ docker-compose run web python3 manage.py migrate
    $ docker-compose up

The site will now run on http://localhost:5000

Running the tests::

    $ docker-compose run web python3 manage.py test

A quick way to run isort and black::

    $ docker-compose run web python3 manage.py migrate

Note that the makefile makes sure the requirements.txt is updated with
"pip-compile" when setup.py or requirements.in changes. You can also run it by
hand.

A requirements.txt file isn't really needed, as it is a library. It was added
to help keep track of versions when updating.


Grabbing production database
----------------------------

Dump::

    $ pg_dump -f sso.dump -F c \
      -h DATABASESERVER -U sso \
      -N topology -T spatial_ref_sys sso

Restore::

    $ pg_restore --no-owner --clean --dbname sso --username buildout --host db
