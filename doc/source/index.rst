Lizard-auth-server, basis for sso.lizard.net
############################################

sso.lizard.net is our Single Sign On server. So: someone only has to log in on
this one website and is (semi-)automatically logged in on our other websites.

The previous version was much too complex, mostly because it mixed
*authentication* and *authorization*. The new SSO only deals with
authentication.

.. glossary::

  authentication
    Authentication means logging in. You prove who you are by giving your
    username and password (or a JWT token). "I am Reinout van Rees".

  authorization
    Authorization means determining what you're allowed to do after you've
    authenticated yourself. "Reinout is allowed to delete existing sluices in
    the Nieuwegein website".

    Authorization thus depends on the kind of contents in the various websites
    and on their internal rights structure. This is different per site, so you
    cannot manage that in a central location.


Explanation
-----------

.. toctree::
   :maxdepth: 2

   explanation_models_rights
   explanation_connect_site
   explanation_admin_usage
   explanation_views
   explanation_api


Reference
---------

.. toctree::
   :maxdepth: 2

   reference_models
   reference_views
   reference_api
   reference_forms

   project
