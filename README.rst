lizard-auth-server
==========================================


.. image:: https://travis-ci.org/lizardsystem/lizard-auth-server.svg?branch=master
    :target: https://travis-ci.org/lizardsystem/lizard-auth-server

.. image:: https://coveralls.io/repos/lizardsystem/lizard-auth-server/badge.svg?branch=master&service=github
  :target: https://coveralls.io/github/lizardsystem/lizard-auth-server?branch=master

Lizard auth server is build upon django-simple-sso_.

It is installed as https://sso.lizard.net, see https://github.com/nens/sso/


Setup
-----

If you get a `Site matching query does not exist` error when you access the
site you need to do something like this::

    $ bin/django shell
    >>> from django.contrib.sites.models import Site
    >>> new_site = Site.objects.create(domain='foo.com', name='foo.com')


Workflow
---------

The workflow follows the django simple sso workflow_.


.. _django-simple-sso: http://pypi.python.org/pypi/django-simple-sso
.. _workflow: https://github.com/ojii/django-simple-sso#workflow


Updating translations
---------------------

Go to the ``lizard_auth_server`` subdirectory and run makemessages and upload
the catalog to transifex::

    $ cd lizard_auth_server
    $ ../bin/django makemessages --all
    $ cd ..
    $ bin/transifex upload_catalog

Then update the NL translation on
https://translations.lizard.net/projects/p/lizardsystem/resource/lizard-auth-server/
and afterwards fetch the latest translations::

    $ bin/transifex fetch

Note: this also fetches af/vi/zh, but we don't translate into those languages
currently. They're ignored in the ``.gitignore`` file.
