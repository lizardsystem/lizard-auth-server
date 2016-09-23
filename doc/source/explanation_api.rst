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
credentials are OK and if the site is allowed.

This way it can be used by lizard-auth-client's authentication backend.

See :class:`lizard_auth_server.views_api_v2.CheckCredentialsView`
