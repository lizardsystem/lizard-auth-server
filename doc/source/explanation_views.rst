Explanation of the user-facing views
====================================

TODO: provide a good entry point at ``/api/v2/`` that points at the various
sub-urls.


``/api/v2/authenticate/``
-------------------------

The lizard-auth-client login action of an SSO-using site redirects to this
URL. The end result is that the user is logged in (with a session cookie) into
both the SSO and the site.


``/api/v2/logout/``
-------------------

The lizard-auth-client logout action of an SSO-using site redirects to this
URL. The end result is that the user is logged out of both the SSO and the
site.
