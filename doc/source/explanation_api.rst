Explanation of how to use the API
=================================


``/api2/``
------------

Startpoint of the API that returns the available urls. This way there's no
need for hardcoded URLs in lizard-auth-client anymore!

See :class:`lizard_auth_server.views_api_v2.StartView`


``/api2/check_credentials/``
------------------------------

Use it to directly check username/password credentials with the SSO. So:
without any user-facing html pages and redirects. Just a check if the
credentials are OK.

This way it can be used by lizard-auth-client's authentication backend.

It returns a dict with the user's username, email, first name and last name.

See :class:`lizard_auth_server.views_api_v2.CheckCredentialsView`


``/api2/new_user/``
------------------------------

Use it to add a new user on a local site and on the SSO. It looks up users by
email and returns the first one found. If not found, it creates a user (in the
SSO). The user has no password and is inactive: they get an activation email
where they can set their password themselves.

The call returns the same dict as the api method above.

See :class:`lizard_auth_server.views_api_v2.NewUserView`


``/api2/organisations/``
------------------------

The SSO maintains a list of organisations so that sites can coordinate data
ownership. The call returns a dict with unique IDs and organisation names.

See :class:`lizard_auth_server.views_api_v2.OrganisationsView`
