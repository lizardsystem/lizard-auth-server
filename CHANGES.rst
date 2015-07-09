Changelog of lizard-auth-server
===================================================


0.6 (unreleased)
----------------

- New API endpoints: get_roles, get_user_organisation_roles


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
