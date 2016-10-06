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


``/api2/activate/``
-------------------

Target of the activation email sent by
:class:`lizard_auth_server.views_api_v2.NewUserView`. The user gets the
standard enter-your-password django form. Afterwards, their account is
activated and they are immediately logged in and redirected to the "success!"
view below.

See :class:`lizard_auth_server.views_api_v2.ActivateAndSetPasswordView`


``/api2/activated/PORTAL_ID/``
------------------------------

"Success!" page after successful activation. It shows a link to the portal
that requested the user creation.

See :class:`lizard_auth_server.views_api_v2.ActivatedGoToPortalView`
