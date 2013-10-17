Changelog of lizard-auth-server
===================================================


0.3 (unreleased)
----------------

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

