lizard-auth-server
==========================================


.. image:: https://travis-ci.org/lizardsystem/lizard-auth-server.svg?branch=master
    :target: https://travis-ci.org/lizardsystem/lizard-auth-server

.. image:: https://coveralls.io/repos/lizardsystem/lizard-auth-server/badge.svg?branch=master&service=github
  :target: https://coveralls.io/github/lizardsystem/lizard-auth-server?branch=master


Lizard auth server is build upon django-simple-sso_.

Workflow
---------

Thie workflow follows the django simple sso workflow_.


.. _django-simple-sso: http://pypi.python.org/pypi/django-simple-sso
.. _workflow: https://github.com/ojii/django-simple-sso#workflow


Updating translations
---------------------

Go to the ``lizard_auth_server`` subdirectory and run makemessages::

    $ cd lizard_auth_server
    $ ../bin/django makemessages --all
    $ bin/translations upload_catalog

Then update the NL translation on
https://translations.lizard.net/projects/p/lizardsystem/resource/lizard-auth-server/
and afterwards fetch the latest translations::

    $ bin/translations fetch

Note: this also fetches af/vi/zh, but we don't translate into those languages
currently. They're ignored in the ``.gitignore`` file.
