# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.conf.urls.defaults import include, patterns, url
from django.conf import settings
from django.contrib import admin
from django.contrib import auth
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured

from lizard_auth_server import views
from lizard_auth_server import forms

def check_settings():
    '''
    Ensure settings are valid, to offer some extra security.
    '''
    if not 'django.middleware.csrf.CsrfViewMiddleware' in settings.MIDDLEWARE_CLASSES:
        raise ImproperlyConfigured('This app REALLY needs django.middleware.csrf.CsrfViewMiddleware.')
    if not getattr(settings, 'USE_TZ', False):
        raise ImproperlyConfigured('Setting USE_TZ = True in your settings is also a good idea.')
    if getattr(settings, 'AUTH_PROFILE_MODULE') != 'lizard_auth_server.UserProfile':
        raise ImproperlyConfigured('Ensure AUTH_PROFILE_MODULE is set to our custom UserProfile model.')
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
    # Private SSO URLs used for internal communication between the servers
    # Note: these are part of the "API" and thus referred to by the client: change them there as well
    url(r'^sso/internal/authenticate/$',  views.AuthenticationApiView.as_view(), name='lizard_auth_server.sso_authenticate'),
    url(r'^sso/internal/get_user/$',      views.GetUserApiView.as_view(),        name='lizard_auth_server.sso_get_user'),
    url(r'^sso/internal/request_token/$', views.RequestTokenView.as_view(),      name='lizard_auth_server.sso_request_token'),
    url(r'^sso/internal/verify/$',        views.VerifyView.as_view(),            name='lizard_auth_server.sso_verify'),
    # Public SSO URLs for use by visitors
    # Note: these are part of the "API" and thus referred to by the client: change them there as well
    url(r'^sso/portal_action/$',   views.PortalActionView.as_view(),   name='lizard_auth_server.sso_portal_action'),
    url(r'^sso/logout_redirect/$', views.LogoutRedirectView.as_view(), name='lizard_auth_server.sso_logout_redirect'),
    url(r'^sso/authorize/$',       views.AuthorizeView.as_view(),      name='lizard_auth_server.sso_authorize'),
    # Override django-auth's default login/logout URLs
    # Note: ensure LOGIN_URL isn't defined in the settings
    url(
        r'^accounts/login/$',
        'django.contrib.auth.views.login',
        {
            'template_name': 'lizard_auth_server/login.html'
        },
        name='login'
    ),
    url(
        r'^accounts/logout/$',
        'django.contrib.auth.views.logout',
        {
            'template_name': 'lizard_auth_server/logged_out.html'
        },
        name='logout'
    ),
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
            'email_template_name': 'lizard_auth_server/password_reset_email.html',
            'subject_template_name': 'lizard_auth_server/password_reset_subject.txt'
            # TODO can't configure email language somehow
        },
        name='password_reset'
    ),
    url(
        r'^password_reset/done/$',
        'django.contrib.auth.views.password_reset_done',
        {
            'template_name': 'lizard_auth_server/password_reset_done.html'
        },
        name='password_reset_done'
    ),
    url(
        r'^reset/(?P<uidb36>[0-9A-Za-z]{1,13})-(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        'django.contrib.auth.views.password_reset_confirm',
        {
            'template_name': 'lizard_auth_server/password_reset_confirm.html'
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
    # URLs for user registration
    url(
        r'^invite/$',
        views.InviteUserView.as_view(),
        name='lizard_auth_server.invite_user'
    ),
    url(
        r'^invite/complete/(?P<invitation_pk>\d+)$',
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
        r'^activation_complete/(?P<activation_key>\w+)$',
        views.ActivationCompleteView.as_view(),
        name='lizard_auth_server.activation_complete'
    ),
)

if settings.DEBUG:
    from django.contrib.staticfiles.urls import staticfiles_urlpatterns
    urlpatterns += staticfiles_urlpatterns()
