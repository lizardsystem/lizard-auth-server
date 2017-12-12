# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.conf import settings
from django.conf.urls import include
from django.conf.urls import patterns
from django.conf.urls import url
from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured
from lizard_auth_server import forms
from lizard_auth_server import views
from lizard_auth_server import views_api
from lizard_auth_server import views_api_v2
from lizard_auth_server import views_sso


def check_settings():
    """
    Ensure settings are valid, to offer some extra security.
    """
    if not ('django.middleware.csrf.CsrfViewMiddleware'
            in settings.MIDDLEWARE_CLASSES):
        raise ImproperlyConfigured(
            'This app REALLY needs django.middleware.csrf.CsrfViewMiddleware.')
    if not getattr(settings, 'USE_TZ', False):
        raise ImproperlyConfigured(
            'Setting USE_TZ = True in your settings is also a good idea.')


check_settings()

admin.autodiscover()

# Trick to override the admin login screen with our custom
# login view.
admin.site.login = login_required(admin.site.login)

urlpatterns = patterns(
    '',
    url(r'^$', views.ProfileView.as_view(), name='index'),
    url(r'^admin/', include(admin.site.urls)),
    url(r'^i18n/', include('django.conf.urls.i18n')),
    url(r'', include('oidc_provider.urls', namespace='oidc_provider')),

    # Version 1 API
    #
    # /api/ and /sso/api/ URLs are mainly used for internal
    # communication between the servers Note: these are referred to by
    # lizard-auth-client: change them in both places
    url(r'^api/authenticate_unsigned/$',
        views_api.AuthenticateUnsignedView.as_view(),
        name='lizard_auth_server.api.authenticate_unsigned'),
    # The next one is used for direct logins via lizard-auth-client's
    # ``backends.py``,
    url(r'^api/authenticate/$',
        views_api.AuthenticateView.as_view(),
        name='lizard_auth_server.api.authenticate'),
    url(r'^api/get_user/$',
        views_api.GetUserView.as_view(),
        name='lizard_auth_server.api.get_user'),
    url(r'^api/get_users/$',
        views_api.GetUsersView.as_view(),
        name='lizard_auth_server.api.get_users'),
    url(r'^api/get_organisations/$',
        views_api.GetOrganisationsView.as_view(),
        name='lizard_auth_server.api.get_organisations'),
    url(r'^api/roles/$',
        views_api.RolesView.as_view(),
        name='lizard_auth_server.api.roles'),
    url(r'^api/user_organisation_roles/$',
        views_api.UserOrganisationRolesView.as_view(),
        name='lizard_auth_server.api.user_organisation_roles'),

    # Version 1 views
    #
    # SSO URLs for use by visitors Note: these are referred to by
    # lizard-auth-client: change them in both places
    url(r'^sso/portal_action/$',
        views_sso.PortalActionView.as_view(),
        name='lizard_auth_server.sso.portal_action'),
    url(r'^sso/logout_redirect/$',
        views_sso.LogoutRedirectView.as_view(),
        name='lizard_auth_server.sso.logout_redirect'),
    url(r'^sso/authorize/$',
        views_sso.AuthorizeView.as_view(),
        name='lizard_auth_server.sso.authorize'),
    # SSO URLs for use by other webservers Note: these are referred to
    # by lizard-auth-client: change them in both places
    url(r'^sso/api/request_token/$',
        views_sso.RequestTokenView.as_view(),
        name='lizard_auth_server.sso.api.request_token'),
    url(r'^sso/api/verify/$',
        views_sso.VerifyView.as_view(),
        name='lizard_auth_server.sso.api.verify'),

    # Version 2 API
    #
    # API calls
    url(r'^api2/$',
        views_api_v2.StartView.as_view(),
        name='lizard_auth_server.api_v2.start'),
    url(r'^api2/check_credentials/$',
        views_api_v2.CheckCredentialsView.as_view(),
        name='lizard_auth_server.api_v2.check_credentials'),
    url(r'^api2/organisations/$',
        views_api_v2.OrganisationsView.as_view(),
        name='lizard_auth_server.api_v2.organisations'),
    url(r'^api2/new_user/$',
        views_api_v2.NewUserView.as_view(),
        name='lizard_auth_server.api_v2.new_user'),
    url(r'^api2/find_user/$',
        views_api_v2.FindUserView.as_view(),
        name='lizard_auth_server.api_v2.find_user'),
    # Views for visitors
    url(r'^api2/login/$',
        views_api_v2.LoginView.as_view(),
        name='lizard_auth_server.api_v2.login'),
    url(r'^api2/logout/$',
        views_api_v2.LogoutView.as_view(),
        name='lizard_auth_server.api_v2.logout'),
    url(r'^api2/logout_redirect_back_to_portal/$',
        views_api_v2.LogoutRedirectBackView.as_view(),
        name='lizard_auth_server.api_v2.logout_redirect_back'),
    url(r'^api2/activate/' +
        '(?P<user_id>[^/]+)/' +
        '(?P<sso_key>[^/]+)/' +
        '(?P<language>[^/]+)/' +
        '(?P<message>[^/]+)$',
        views_api_v2.ActivateAndSetPasswordView.as_view(),
        name='lizard_auth_server.api_v2.activate-and-set-password'),
    url(r'^api2/activated/(?P<portal_pk>[^/]+)/$',
        views_api_v2.ActivatedGoToPortalView.as_view(),
        name='lizard_auth_server.api_v2.activated-go-to-portal'),

    # Override django-auth's default login/logout URLs
    # Note: ensure LOGIN_URL isn't defined in the settings
    url(r'^accounts/login/$',
        'django.contrib.auth.views.login',
        {'template_name': 'lizard_auth_server/login.html',
         'authentication_form': forms.LoginForm},
        name='login'),
    url(r'^accounts/logout/$',
        'django.contrib.auth.views.logout',
        {
            'template_name': 'lizard_auth_server/logged_out.html'
        },
        name='logout'),
    # Override django-auth's default profile URL
    # Note: ensure LOGIN_URL_REDIRECT isn't defined in the settings
    url(
        r'^accounts/profile/$',
        views.ProfileView.as_view(),
        name='profile'
    ),
    # Override django-auth's password change URLs
    url(
        r'^password_change/$',
        'django.contrib.auth.views.password_change',
        {
            'template_name': 'lizard_auth_server/password_change_form.html',
            'password_change_form': forms.PasswordChangeForm
        },
        name='password_change'
    ),
    url(
        r'^password_change/done/$',
        'django.contrib.auth.views.password_change_done',
        {
            'template_name': 'lizard_auth_server/password_change_done.html'
        },
        name='password_change_done'
    ),
    # Override django-auth's password reset URLs
    url(r'^password_reset/$',
        'django.contrib.auth.views.password_reset',
        {
            'template_name': 'lizard_auth_server/password_reset_form.html',
            'email_template_name':
            'lizard_auth_server/password_reset_email.html',
            'subject_template_name':
            'lizard_auth_server/password_reset_subject.txt'
            # TODO can't configure email language somehow
        },
        name='password_reset'),
    url(
        r'^password_reset/done/$',
        'django.contrib.auth.views.password_reset_done',
        {
            'template_name': 'lizard_auth_server/password_reset_done.html'
        },
        name='password_reset_done'
    ),
    url(
        r'^reset/(?P<uidb64>[0-9A-Za-z]{1,13})-'
        r'(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        'django.contrib.auth.views.password_reset_confirm',
        {
            'template_name': 'lizard_auth_server/password_reset_confirm.html',
            'set_password_form': forms.SetPasswordForm
        },
        name='password_reset_confirm'
    ),
    url(
        r'^reset/done/$',
        'django.contrib.auth.views.password_reset_complete',
        {
            'template_name': 'lizard_auth_server/password_reset_complete.html'
        },
        name='password_reset_complete'
    ),
    # v1 URLs for user invitation / activation
    url(
        r'^invite/$',
        views.InviteUserView.as_view(),
        name='lizard_auth_server.invite_user'
    ),
    url(
        r'^invite/complete/(?P<invitation_pk>\d+)/$',
        views.InviteUserCompleteView.as_view(),
        name='lizard_auth_server.invite_user_complete'
    ),
    url(
        r'^activate/(?P<activation_key>\w+)/$',
        views.ActivateUserView1.as_view(),
        name='lizard_auth_server.activate'
    ),
    url(
        r'^activate_step_2/(?P<activation_key>\w+)/$',
        views.ActivateUserView2.as_view(),
        name='lizard_auth_server.activate_step_2'
    ),
    url(
        r'^activation_complete/(?P<activation_key>\w+)/$',
        views.ActivationCompleteView.as_view(),
        name='lizard_auth_server.activation_complete'
    ),
    url(
        r'^edit_profile/$',
        views.EditProfileView.as_view(),
        name='lizard_auth_server.edit_profile'
    ),
    # URLs for third-party apps.
    url(
        r'^jwt/$',
        views.JWTView.as_view(),
        name='lizard_auth_server.jwt'
    ),

    # URLs for debugging portal access.
    url(
        r'^access-to-portal/(?P<portal_pk>\d+)/$',
        views.AccessToPortalView.as_view(),
        name='lizard_auth_server.access_to_portal'
    ),
    url(
        r'^access-to-portal/(?P<portal_pk>\d+)/(?P<user_pk>\d+)/$',
        views.AccessToPortalView.as_view(),
        name='lizard_auth_server.access_to_portal'
    ),

)

if settings.DEBUG:
    from django.contrib.staticfiles.urls import staticfiles_urlpatterns
    urlpatterns += staticfiles_urlpatterns()
