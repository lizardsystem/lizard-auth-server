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

Users can be created via the API by a portal. They then need to get an email
with an invitation to set their password (and thereby to enable their
account).

Alternative: a user creates their own account. No password, that's handled in
the invitation email. Note: not directly needed.

Edit page for name and email.

"forgot my account" page


Notities
--------

Beetje naar django-registration gekeken. Lijkt toch geen goede match. Wel een
paar goede ideeen zoals methodes op de objectmanager
(.send_activation_email(), .create_inactive_user()).

Wijziging tov vorige: je wilt gelijk een gebruiker hebben!!! Dus heb je de
username nodig.


api komt binnen, user wordt aangemaakt.

=> huidige methode naar manager verplaatsen.

TODO: Unusable wachtwoord instellen. Activatiemail sturen.

Hiervoor huidige code bekijken.
