Changelog of lizard-auth-server
===================================================


0.1 (unreleased)
----------------

- Initial project structure created with nensskel 1.30.dev0.

- First release of lizard-auth-server based on a heavily modified
  django-simple-sso.

- Roles, Organizations and related data are now part of
  lizard_auth_server.

- Information about the user's roles in organization is passed from
  VerifyView, along with information about the user. This is ignored
  by old versions of lizard_auth_client but can be used by a new
  version to construct the same information at the Portal side.

