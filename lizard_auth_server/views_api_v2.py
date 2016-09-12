"""
V2 API
"""
import datetime
import logging
import json
# py3 only:
from urllib.parse import urljoin, urlparse, urlencode

from django.conf import settings
from django.contrib.auth import authenticate as django_authenticate
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.template.context import RequestContext
from django.template.response import TemplateResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import View
import jwt

from lizard_auth_server import forms
from lizard_auth_server.views_sso import (
    ProcessGetFormView,
    domain_match,
    FormInvalidMixin,
)
from lizard_auth_server.models import Profile


logger = logging.getLogger(__name__)
JWT_EXPIRATION = datetime.timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)


# Copied from views_sso.py
def get_domain(form):
    """Return domain for the redirect back to the site.

    Normally, the ``redirect_url`` is used. If your server is known under
    several domains, you can pass a ``domain`` GET parameter.

    Note: the domain can also have an extra path element, so
    http://some.where/something is allowed, if needed.

    """
    portal_redirect = form.site.redirect_url
    domain = form.cleaned_data.get('domain', None)

    # BBB, previously the "next" parameter was used, but django itself also
    # uses it, leading to conflicts. IF "next" starts with "http", we use it
    # and otherwise we omit it.
    next = form.cleaned_data.get('next', None)
    if next:
        if next.startswith('http'):  # Includes https :-)
            domain = next

    if domain is None:
        return portal_redirect
    netloc = urlparse(domain)[1]
    if netloc == '':
        return urljoin(portal_redirect, domain)
    if form.site.allowed_domain != '' \
            and domain_match(netloc, form.site.allowed_domain):
        return domain
    return portal_redirect


# Copied from views_sso.py
def construct_user_data(user=None, profile=None):
    """
    Construct a dict of information about a user object,
    like first_name, and permissions.

    Older versions of this server did not send information about
    roles, and only a single organisation name. Older clients still
    expect that, so we need to stay backward compatible.
    """
    if user is None:
        user = profile.user
    if profile is None:
        profile = user.profile
    data = {}
    for key in ['pk', 'username', 'first_name', 'last_name',
                'email', 'is_active']:
        data[key] = getattr(user, key)
    data['company'] = str(profile.company)
    # datetimes should be serialized to an iso8601 string
    data['created_at'] = profile.created_at.isoformat()
    return data


class AuthenticateView(FormInvalidMixin, ProcessGetFormView):
    form_class = forms.JWTDecryptForm

    def form_valid(self, form):
        self.domain = get_domain(form)
        self.site = form.site
        if self.request.user.is_authenticated():
            return self.form_valid_authenticated()
        return self.form_valid_unauthenticated(
            form.cleaned_data.get('force_sso_login', True))

    def form_valid_authenticated(self):
        """
        Called when login succeeded.
        """
        if self.has_access():
            return self.success()
        return self.access_denied()

    def build_login_url(self):
        """
        Store the authorize view (most likely the current view) as
        "next" page for a login page.
        """
        nextparams = {
            'message': self.request.GET['message'],
            'key': self.request.GET['key'],
        }
        params = urlencode([(
            'next',
            '%s?%s' % (
                reverse('lizard_auth_server.api_v2.authenticate'),
                urlencode(nextparams))
        )])
        return '%s?%s' % (reverse('django.contrib.auth.views.login'), params)

    def build_back_to_portal_url(self):
        """Redirect user back to the portal, without logging him in."""
        return urljoin(self.domain, 'sso/local_not_logged_in/')

    def form_valid_unauthenticated(self, force_sso_login):
        """
        Redirect user to login page if force_sso_login == True, else, return
        without having to log in.
        """
        if force_sso_login:
            # Typical situation -- force the user to login.
            return HttpResponseRedirect(self.build_login_url())
        else:
            # Return the unauthenticated user back to the portal.
            return HttpResponseRedirect(self.build_back_to_portal_url())

    def has_access(self):
        """
        Check whether the user has access to the site.
        """
        try:
            profile = self.request.user.profile
        except Profile.DoesNotExist:
            return False
        return profile.has_access(self.site)

    def success(self):
        payload = {
            'key': self.site.sso_key,
            # Dump all relevant data:
            'user': json.dumps(construct_user_data(self.request.user)),
            # Set timeout
            'exp': datetime.datetime.utcnow() + JWT_EXPIRATION,
            }
        signed_message = jwt.encode(payload, self.site.sso_secret,
                                    algorithm='HS256')
        params = {
            'message': signed_message,
            }
        url = urljoin(self.domain, 'sso/local_login/')
        url_with_params = '%s?%s' % (url, urlencode(params))
        return HttpResponseRedirect(url_with_params)

    def access_denied(self):
        """
        Show a user-friendly access denied page.
        """
        context = RequestContext(self.request,
                                 {'login_url': self.build_login_url()})
        return TemplateResponse(
            self.request,
            'lizard_auth_server/access_denied.html',
            context,
            status=403
        )


class VerifyCredentialsView(FormInvalidMixin, ProcessGetFormView):
    """View to simply verify credentials, used by APIs.

    A username+password is passed in a JWT signed form (so: in plain text). We
    verify if the password is OK and whether the user has access to the
    site. No redirects to forms, just a '200 OK' when the credentials are OK
    and an error code if not.

    """
    form_class = forms.JWTDecryptForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(VerifyCredentialsView, self).dispatch(request, *args, **kwargs)

    @method_decorator(sensitive_post_parameters('message'))
    def get(self, request, *args, **kwargs):
        return super(VerifyCredentialsView, self).get(request, *args, **kwargs)

    def form_valid(self, form):
        # The JWT message is OK, now verify the username/password and send
        # back a reply
        user = django_authenticate(username=form.cleaned_data.get('username'),
                                   password=form.cleaned_data.get('password'))
        if not user:
            raise PermissionDenied("Login failed")
        if not user.profile.has_access(form.site):
            raise PermissionDenied("No access to this site")

        user_data = construct_user_data(user=user)
        return HttpResponse(json.dumps({'user': user_data}),
                            content_type='application/json')


class LogoutView(FormInvalidMixin, ProcessGetFormView):
    """
    View for logging out.
    """
    form_class = forms.JWTDecryptForm

    def form_valid(self, form):
        next_url = reverse('lizard_auth_server.api_v2.logout_redirect')
        next_params = {
            'message': self.request.GET['message'],
            'key': self.request.GET['key'],
        }

        # after logout redirect user to the site
        params = urlencode({
            'next': '%s?%s' % (next_url, urlencode(next_params))
            })
        url = '%s?%s' % (reverse('django.contrib.auth.views.logout'),
                         params)
        # TODO: why can't I redirect immediately to the Site using
        # the next parameter?
        return HttpResponseRedirect(url)


class LogoutRedirectView(FormInvalidMixin, ProcessGetFormView):
    """
    View that redirects the user to the logout page of the portal.
    """
    form_class = forms.JWTDecryptForm

    def form_valid(self, form):
        url = urljoin(get_domain(form), 'sso/local_logout/')
        return HttpResponseRedirect(url)
