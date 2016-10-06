Models and rights
=================

The SSO has three main models:

.. glossary::

  user profile
    Basically users that log in.

  organisation
    Only used to have a name and ID for organisations. It has nothing to do
    with users and portals whatsoever.

  portal
    A portal that's using the SSO. You need SSO admin access to add one. Used
    to protect the traffic between portal and SSO.


User profile
------------

Users can be created via the API by a portal. They then get an email
with an activation link to set their password.
