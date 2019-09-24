Changelog of lizard-auth-server
===================================================


2.22 (unreleased)
-----------------

- Made organisations also searchable by unique_id in the Django admin.

- Updated test setup so that the automatic tests run once again on travis-ci.

- Invitation emails: using separate templates per language instead of `.po`
  files: easier to switch the wording per language.

- Invitation emals: using both ``.txt`` and ``.html`` templates. This way we
  can send html emails with a visually shorter invitation link.


2.21 (2018-03-16)
-----------------

- Support display&deletion of openID connect "user consents".


2.20 (2017-12-14)
-----------------

- Removed now-unused and now-confusing listing of portals and organisations on
  the homepage.

  Now-unused: only one or two sites use the access functionality, but these
  don't use organisations.

  Removed: it is still there for superusers for debug purposes.


2.19 (2017-12-13)
-----------------

- Added django-oidc-provider so that we can work as "openID connect
  provider".

  Adjusted scopes and userinfo to the minimum that we want. Note: in the sso,
  add the following setting::

    OIDC_USERINFO = 'lizard_auth_server.oidc.userinfo'


2.18 (2017-12-08)
-----------------

- Added newline in activation email (cosmetic reason).

- New behaviour when adding users with existing username via api2/new_user/:
  * Old: HTTP 500 statuscode with empty content
  * New: HTTP 409 (conflict) statuscode with error message in (text) content

- New behaviour when adding users with existing email via api2/new_user/:
  * Old: HTTP 200 statuscode with userdata in (json) content
  * New: HTTP 409 (conflict) statuscode with error message in (text) content

  Note: Use api2/find_user/ to search for users.

- Added related_name from User to Token so that there's no conflict with
  django-oidc-provider.


2.17 (2017-08-30)
-----------------

- Show the username in the activation email. (2.16 fixed the old
  now-mostly-unused invitation email, this fixes the new v2 activation
  email).


2.16 (2017-07-05)
-----------------

- Pin zc.buildout to 2.9.4, setuptools to 36.0.1 and six to 1.10.0.

- If an Invitation instance has a user, render that user's username in the
  invitation email.

- Add tests for the invitation email.


2.15 (2016-12-08)
-----------------

- JWT form errors in API requests now return a text message instead of
  html. So JWT errors now also return a meaningful HTTP response to the
  client.


2.14 (2016-12-07)
-----------------

- Fixed blunder in the example settings you should paste from the admin into
  your site: ``SSO_USE_V2_LOGIN`` was shown as ``SSO_USE_V2_login`` (note the
  lowercase "login").... Reinout says sorry.

- Not raising ValidationError anymore in form_valid(). In form_valid, all
  validation has already happend, so a ValidationError results in a generic
  "error 500" page.

  The SSO now returns return meaningful HTTP responses with some explanatory
  text. Much easier to debug on the receiving end.


2.13 (2016-11-11)
-----------------

- Bugfix: email lookup, when looking for users in the V2 API, is now
  case-insensitive.

- Added ``/api2/find_user/`` in addition to ``/api2/new_user/``. This new view
  only needs an email address and then looks up a matching user. So you don't
  need to pass first/last/username. It will only look, though, it won't
  create.


2.12 (2016-10-19)
-----------------

- Only showing the ``visit_url`` in the "you have activated your account"
  template instead of also the (mostly internally used) portal name.


2.11 (2016-10-19)
-----------------

- Bugfix: the optional ``visit_url`` is now also used in the email that is
  send out to the new user.


2.10 (2016-10-19)
-----------------

- Allowing to pass a language code when adding a new user.

- Updated translations.

- The ``/api2/check_credentials/`` check now also verifies if a user is
  active. Fixes #62.

- A ``visit_url`` can now be passed when creating a new user. It will be shown
  on the "ready to go to the portal" page instead of the portal's default
  ``visit_url`` when available. Fixes #61.

- Username field on the login form now has autofocus. Fixes #11. See
  http://stackoverflow.com/a/31032262/27401 .


2.9 (2016-10-06)
----------------

- Removed virtually unused address/phone/title fields on user profile. The new
  v2 api won't use them anyway.

- Users created through the ``/api2/new_user/`` API call now get an email with
  an activation link.


2.8 (2016-10-04)
----------------

- Bugfix: invitations didn't work because ``transaction.commit_on_success()``
  is ``transaction.atomic()`` now.


2.7 (2016-10-03)
----------------

- Bugfix: fixed password reset email template, it didn't work with newer
  django versions.


2.6 (2016-09-30)
----------------

- Added ``/api2/organisations/`` that lists the organisation names plus
  unique ID.

- Added more logging and made 'duplicate username' error, when creating a
  user, more explicit.


2.5 (2016-09-23)
----------------

- Added a ``/api2/new_user/`` endpoint that a site can use to create/find a
  user based on their email address.


2.4 (2016-09-23)
----------------

- The endpoint URLs returned by ``/api2/`` are inclusive the domain name,
  now.


2.3 (2016-09-23)
----------------

- V2 2.0..... Removed the new profile/company/site models.

- The new v2 API now uses the existing userprofile/organisation/portal models.

- The new v2 API doesn't use the still-existing roles stuff and it also
  doesn't look at whether a userprofile is configured to access a portal: it
  only does authentication.

- The v2 API urls have been renamed for consistency/clarity. A new
  ``/api2/`` endpoint lists the URLs of the other API endpoints, so moving
  over to the new structure should be easy.

- The ``/api/v2/`` urls now start with ``/api2/`` as ``/api/*`` is blocked by
  nginx as that was previously internal-network-only accessible.


2.2 (2016-09-14)
----------------

- Added ``/api/v2/check_credentials/`` for checking credentials, analogous
  to the old ``/api/authenticate/``. Used by APIs to simply verify
  username/password credentials without any html interaction and redirects.


2.1 (2016-08-30)
----------------

- Added custom object managers for Profile and Company to easily restrict
  queries to those you can actuall edit.

- The old to-be-removed-eventually models now have their names enclosed in
  parenthesis. So ``(portal)`` instead of ``portal``. This makes it clear
  which models are new and which ones are old.

- Added migration steps that adds a new-style Profile for all users that don't
  have one yet. Needed when moving from the old to the new system.

- Fixed inflated user profile count on Organisation.

- Added admin action to convert an Organisation into a Company, including
  moving over user profiles either as member or as guest (when the user is
  already a member elsewhere).

- Improved the admin. You can easily switch between Company and Profile
  now. Added sorting. Added dutch translations.

- Added admin action for Profile to turn a member into a guest instead.


2.0 (2016-07-07)
----------------

- Added JWT expiration time of 15 minutes.

- Added new V2 API in separate endpoints which uses JWT.

- Added new models for SSO refactoring.

- Put user creation signals handlers into seperate module.

- Some py3 changes.

- Renamed 'return_unauthenticated'.

- A user arriving at the SSO server after being redirected there can
  now use a "return_unauthenticated" URL attribute. If the user is
  already logged in on the SSO server, redirects are set up so that he
  will be logged in on the site he was redirected from.

  If he is not, then if return_unauthenticated is False (the default,
  and the old behaviour), then he will be forced to log in before
  being redirected back.

  If return_unauthenticated, redirect the user back without logging in
  (to lizard-auth-client's /sso/local_not_logged_in/ URL).

  This enables a "attempt to auto-login if possible, but don't require it"
  workflow that is sometimes helpful.

- Python 3 setup and test fixes.

1.7 (2016-06-14)
----------------

- Upgraded to Django 1.9.7.


1.6 (2016-02-11)
----------------

- Added support for JSON Web Tokens.
  [byrman]

- Fixed wrong variable in log message.
  [reinout]


1.5 (2015-11-27)
----------------

- Moved ``.clean()`` method from the UserProfile model to a form. M2M fields
  cannot be checked by a model's ``.clean()`` as it always looks at the
  existing, old, data.
  [reinout]


1.4 (2015-11-27)
----------------

- One and only one 3di billing role is allowed for users with access to the 3di
  portal.
  [reinout]

- Added check that 3di billing isn't enabled 'for all users' of an
  organisation.
  [reinout]

- Added link to edit a user's profile at the end of the registration
  steps. This assumes the lizard6-style manual enabling of users. The previous
  link was in an unusable place.
  [reinout]


1.3 (2015-11-16)
----------------

- Added role inheritance, mainly based on an idea by Remco. One portal's role
  can point at other portals' roles as "inheriting roles". The other way
  around, the original role then becomes those other roles' "base role".

  If an organisation has an organisation role pointing at the base role *and*
  an organisation role pointing at the inheriting role, that inheriting role
  is available to the user (provided he has access to one of those two
  organisation roles).
  [reinout]

- Beautified the main SSO page ("my profile") and made it more usable. Nicer
  list of organisations; "definition list" instead of "table" for the user
  profile data; all actions in one spot.
  [reinout]

- Added separate page for viewing your permissions (which means
  "organisation-role-mappings") per portal, linked from the main portal page.

  As staff member, you can see detailed debug information to troubleshoot
  permissions. You can also view other users' permission information,
  essential for getting permissions right.
  [reinout]

- OrganisationRole has a manager now that automatically sets
  ``select_related()`` to select roles, portals and organisations. Otherwise
  to have to add select_related in way too many places. (Uncovered by testing
  with the django debug toolbar). Same for Role.
  [reinout]

- Added ``select_related`` in several places to lower the amount of queries,
  especially in the admin.
  [reinout]


1.2 (2015-11-02)
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
