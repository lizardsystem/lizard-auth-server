Explanation of the user-facing views
====================================

Note: the actual URLs need to be taken from the ``/api2/`` endpoint. Don't
hardcode them.

See :meth:`lizard_auth_server.views_api_v2.LogoutView.get`


``/api2/login/``
------------------

The lizard-auth-client login action of an SSO-using site redirects to this
URL. The end result is that the user is logged in (with a session cookie) into
both the SSO and the site.

See :class:`lizard_auth_server.views_api_v2.LoginView`


``/api2/logout/``
-------------------

The lizard-auth-client logout action of an SSO-using site redirects to this
URL. The end result is that the user is logged out of both the SSO and the
site.

See :class:`lizard_auth_server.views_api_v2.LogoutView`
