Changelog of lizard-auth-server
===================================================


1.2 (unreleased)
----------------

- Increased the test coverage.
  [reinout]

- Fixed bug with ``__unicode__`` method on ``UserProfile``.
  [reinout]


1.1.1 (2015-10-30)
------------------

- Re-release of 1.1, I accidentally made it on the branch.
  [reinout]


1.1 (2015-10-30)
----------------

- Internal change: sorting the imports with ``bin/isort
  lizard_auth_server/*py`` now (and thus with ``.isort.cfg``). Note: the
  imports aren't grouped in the regular 3 "pep8" groups. This is an experiment
  inspired by Plone.
  [reinout]

- Huge translation update. Everything is marked as translatable. Models and
  fields now have translatable names. Translation is set up to use
  https://translations.lizard.net, with instructions in the
  ``README.rst``. And... everything has been translated into Dutch.
  [reinout]

- Huge admin update for the changelist pages. Better sorting, more columns,
  more search, more filtering, more links to related objects.
  [reinout]

- Huge update for the object edit pages. Better order, better fields, editable
  yes/no, etcetera. **Most important change**: horizontal filtering for
  portals instead of a long ctrl-click-to-select-multiple list. Also added
  inlines for easy editing roles on portals and editing organisation roles on
  organisations.
  [reinout]


1.0 (2015-09-24)
----------------

- The parameter to redirect to a different domain is now called ``domain``
  instead of ``next``. ``next`` is already used by django itself and it
  interferes too much.

  The ``next`` parameter is still supported if it starts with ``http`` for
  temporary backwards compatibility.
  [reinout]


0.8 (2015-09-18)
----------------

- Showing all organizations for a user.
  [remco]


0.7 (2015-08-26)
----------------

- The "allowed domain" setting for a site can now include multiple
  space-separated patterns.
  [byrman]

- Upgraded the test setup so that coverage is now also reported. We're at 56%.
  [reinout]


0.6 (2015-07-14)
----------------

- New API endpoints: get_roles, get_user_organisation_roles.


0.5 (2015-04-17)
----------------

- Compatibility with django 1.6: uidb64 instead of uidb36 hashed user IDs in
  password reset form. Password reset was broken after our move to django 1.6.

  See
  https://docs.djangoproject.com/en/1.6/releases/1.6/#django-contrib-auth-password-reset-uses-base-64-encoding-of-user-pk


0.4 (2015-01-12)
----------------

- Added support for login on custom domains.


0.3 (2014-11-19)
----------------

- Added an internal API call that returns all organisations, so that
  they can be added to clients before any user of that organisation
  has logged in (lizard_auth_client has a
  ``synchronise_organisations()`` function).


0.2.5 (2014-05-16)
------------------

- Bug fix: do not crash on profile-less users.


0.2.4 (2013-10-17)
------------------

- More convenient Django Admin screens.


0.2.3 (2013-10-08)
------------------

- Fix bug that caused lizard-auth-server to return non-distinct
  organisation_roles (issue3).


0.2.2 (2013-09-04)
------------------

- Fix bug that caused activation to fail (organisations not saved
  correctly).


0.2.1 (2013-09-03)
------------------

- Failed to check in a crucial change.


0.2 (2013-09-02)
----------------

- Bug fix: only pass organisation-roles belonging to the current
  portal


0.1 (2013-08-30)
----------------

- Initial project structure created with nensskel 1.30.dev0.

- First release of lizard-auth-server based on a heavily modified
  django-simple-sso.

- Roles, Organisations and related data are now part of
  lizard_auth_server.

- Information about the user's roles in organisation is passed from
  VerifyView, along with information about the user. This is ignored
  by old versions of lizard_auth_client but can be used by a new
  version to construct the same information at the Portal side.
