# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.conf import settings
from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.http import HttpResponseRedirect
from django.template.context import RequestContext
from django.template.response import TemplateResponse
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext as _
from django.views.decorators.cache import never_cache
from django.views.generic.base import View
from django.views.generic.edit import FormMixin
from itsdangerous import URLSafeTimedSerializer
from lizard_auth_server import forms
from lizard_auth_server.models import Token
from lizard_auth_server.models import UserProfile
from lizard_auth_server.views import ErrorMessageResponse

import datetime
import json
import logging
import pytz


try:
    from urlparse import urljoin, urlparse
    from urllib import urlencode
except ImportError:
    from urllib.parse import urljoin, urlparse, urlencode


logger = logging.getLogger(__name__)

TOKEN_TIMEOUT = datetime.timedelta(minutes=settings.SSO_TOKEN_TIMEOUT_MINUTES)


class ProcessGetFormView(FormMixin, View):
    """
    A view which validates a form using GET parameters
    instead of POST.

    See Django's ProcessFormView.
    """
    def get_form(self, form_class):
        return form_class(self.request.GET)

    @method_decorator(never_cache)
    def get(self, request, *args, **kwargs):
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)


class PortalActionView(ProcessGetFormView):
    """
    View that allows portals to do some miscellaneous actions,
    like logging out.
    """
    form_class = forms.DecryptForm

    def form_valid(self, form):
        if form.cleaned_data['action'] == 'logout':
            nextparams = {
                'message': self.request.GET['message'],
                'key': self.request.GET['key'],
            }
            # after logout, redirect user to the LogoutRedirectView,
            # which should redirect the user back to the portal again.
            nextparams = urlencode(
                [('next', '%s?%s' % (
                  reverse('lizard_auth_server.sso.logout_redirect'),
                  urlencode(nextparams))
                  )])
            url = '%s?%s' % (reverse('django.contrib.auth.views.logout'),
                             nextparams)
            return HttpResponseRedirect(url)
        return HttpResponseBadRequest('Unknown action')

    def form_invalid(self, form):
        logger.error('Error while decrypting form: %s',
                     form.errors.as_text())
        return ErrorMessageResponse(self.request,
                                    _('Communication error.'),
                                    400)


class LogoutRedirectView(ProcessGetFormView):
    """
    View that redirects the user to the logout page of the portal.
    """
    form_class = forms.DecryptForm

    def form_valid(self, form):
        if form.cleaned_data['action'] == 'logout':
            url = urljoin(get_domain(form), 'sso/local_logout') + '/'
            return HttpResponseRedirect(url)
        else:
            return HttpResponseBadRequest('Unknown action')

    def form_invalid(self, form):
        logger.error('Error while decrypting form: %s',
                     form.errors.as_text())
        return ErrorMessageResponse(self.request,
                                    _('Communication error.'),
                                    400)


class RequestTokenView(ProcessGetFormView):
    """
    Request Token Request view called by the portal application to obtain a
    one-time Request Token.
    """
    form_class = forms.DecryptForm

    def form_valid(self, form):
        token = Token.objects.create_for_portal(form.portal)
        params = {
            'request_token': token.request_token
        }
        # encrypt the token with the secret key of the portal
        data = URLSafeTimedSerializer(token.portal.sso_secret).dumps(params)
        return HttpResponse(data)

    def form_invalid(self, form):
        logger.error('Error while decrypting form: %s',
                     form.errors.as_text())
        return HttpResponseBadRequest('Bad signature')


class AuthorizeView(ProcessGetFormView):
    """
    The portal get's redirected to this view with the `request_token` obtained
    by the Request Token Request by the portal application beforehand.

    This view checks if the user is logged in on the server application and if
    that user has the necessary rights.

    If the user is not logged in, the user is prompted to log in.
    """
    form_class = forms.DecryptForm

    def form_valid(self, form):
        request_token = form.cleaned_data['request_token']
        try:
            self.token = Token.objects.get(request_token=request_token,
                                           portal=form.portal,
                                           user__isnull=True)
        except Token.DoesNotExist:
            return HttpResponseForbidden('Invalid request token')
        if self.check_token_timeout():
            self.domain = get_domain(form)
            if self.request.user.is_authenticated():
                return self.form_valid_authenticated()
            return self.form_valid_unauthenticated(
                form.cleaned_data.get('return_unauthenticated', False))
        return self.token_timeout()

    def form_invalid(self, form):
        logger.error('Error while decrypting form: %s',
                     form.errors.as_text())
        return ErrorMessageResponse(self.request,
                                    _('Communication error.'),
                                    400)

    def check_token_timeout(self):
        delta = datetime.datetime.now(tz=pytz.UTC) - self.token.created
        return delta <= TOKEN_TIMEOUT

    def token_timeout(self):
        self.token.delete()
        return ErrorMessageResponse(
            self.request, _('Token timed out. Please return to the portal '
                            'to get a fresh token.'), 403)

    def form_valid_authenticated(self):
        """
        Called then login succeeded.
        """
        if self.has_access():
            return self.success()
        return self.access_denied()

    def has_access(self):
        """
        Check whether the user has access to the portal.
        """
        if not self.request.user.is_active:
            # extra check: should not be necessary as inactive users can't
            # login anyway
            return False
        # check whether the UserProfile object is related to this Portal
        try:
            # get_profile is deprecated in Django >= 1.7
            # profile = self.request.user.get_profile()
            profile = self.request.user.user_profile
        except UserProfile.DoesNotExist:
            return False
        return profile.has_access(self.token.portal)

    def success(self):
        params = {
            'request_token': self.token.request_token,
            'auth_token': self.token.auth_token
        }
        # encrypt the tokens with the secret key of the portal
        message = URLSafeTimedSerializer(self.token.portal.sso_secret).dumps(
            params)
        # link the user model to the token model, so we can return the
        # proper profile when the SSO client calls the VerifyView
        self.token.user = self.request.user
        self.token.save()
        # redirect user back to the portal
        url = urljoin(self.domain, 'sso/local_login/')
        url = '%s?%s' % (url, urlencode({'message': message}))
        return HttpResponseRedirect(url)

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
                reverse('lizard_auth_server.sso.authorize'),
                urlencode(nextparams))
        )])
        return '%s?%s' % (reverse('django.contrib.auth.views.login'), params)

    def build_back_to_portal_url(self):
        """Redirect user back to the portal, without logging him in."""
        return urljoin(self.domain, 'sso/local_not_logged_in/')

    def form_valid_unauthenticated(self, return_unauthenticated):
        """
        Redirect user, to login page if return_unauthenticated == False.
        """
        if return_unauthenticated:
            # Return the unauthenticated user back to the portal.
            return HttpResponseRedirect(self.build_back_to_portal_url())
        else:
            # Typical situation -- force the user to login.
            return HttpResponseRedirect(self.build_login_url())


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
        # get_profile is deprecated in Django >= 1.7
        # profile = user.get_profile()
        profile = user.user_profile
    data = {}
    for key in ['pk', 'username', 'first_name', 'last_name',
                'email', 'is_active', 'is_staff', 'is_superuser']:
        data[key] = getattr(user, key)
    data['permissions'] = []
    for perm in user.user_permissions.select_related('content_type').all():
        data['permissions'].append({
            'content_type': perm.content_type.natural_key(),
            'codename': perm.codename,
        })

    # For backward compatibility, if the user has at least one
    # organisation, send then name of one of them.
    data['organisation'] = profile.organisation

    # datetimes should be serialized to an iso8601 string
    data['created_at'] = profile.created_at.isoformat()

    return data


def construct_organisation_role_dict(organisation_roles):
    """Return a dict with 3 keys: organisations, roles, and organisation_roles.

    Args:
        organisation_roles: an iterable of OrganisationRoles.

    """
    data = {}

    # Defensive programming: make sure we have a unique set of
    # organisation_roles. At the moment of writing, models.
    # UserProfile.all_organisation_roles() does not...

    organisation_roles = set(organisation_roles)
    organisations = set(obj.organisation for obj in organisation_roles)
    roles = set(obj.role for obj in organisation_roles)

    data['organisation_roles'] = [
        [obj.organisation.unique_id, obj.role.unique_id]
        for obj in organisation_roles
        ]
    data['organisations'] = [obj.as_dict() for obj in organisations]
    data['roles'] = [obj.as_dict() for obj in roles]

    return data


def get_domain(form):
    """Return domain for the redirect back to the site.

    Normally, the ``redirect_url`` is used. If your server is known under
    several domains, you can pass a ``domain`` GET parameter.

    Note: the domain can also have an extra path element, so
    http://some.where/something is allowed, if needed.

    """
    portal_redirect = form.portal.redirect_url
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
    if form.portal.allowed_domain != '' \
            and domain_match(netloc, form.portal.allowed_domain):
        return domain
    return portal_redirect


def domain_match(domain, suffix):
    """Test if `domain` ends with `suffix`.

    Args:
       domain (str): a domain name.
       suffix (str): a string the domain name should end with. Multiple
         suffixes are possible and should be separated by whitespace,
         for example: 'lizard.net ddsc.nl'.

    Returns:
       bool: True if domain ends with the specified suffix, False otherwise.

    """
    return domain.endswith(tuple(suffix.split()))


class VerifyView(ProcessGetFormView):
    """
    View called by the portal application to verify the Auth Token passed by
    the portal request as GET parameter with the server application
    """
    form_class = forms.DecryptForm

    def get_user_json(self):
        """
        Returns the JSON string representation of the user object for a portal.
        """
        profile = self.token.user.user_profile
        data = construct_user_data(profile=profile)
        return json.dumps(data)

    def get_organisation_roles_json(self, portal):
        profile = self.token.user.user_profile
        data = construct_organisation_role_dict(
            profile.all_organisation_roles(portal))
        return json.dumps(data)

    def form_valid(self, form):
        auth_token = form.cleaned_data['auth_token']
        try:
            self.token = Token.objects.get(
                auth_token=auth_token, user__isnull=False, portal=form.portal)
        except Token.DoesNotExist:
            return HttpResponseForbidden('Invalid auth token')
        # get some metadata about the user, so we can construct a user on the
        # SSO client
        params = {
            'user': self.get_user_json(),
            'roles': self.get_organisation_roles_json(form.portal)
        }
        # encrypt the data
        data = URLSafeTimedSerializer(self.token.portal.sso_secret).dumps(
            params)
        # disable the token
        self.token.delete()
        return HttpResponse(data)

    def form_invalid(self, form):
        logger.error('Error while decrypting form: %s',
                     form.errors.as_text())
        return HttpResponseBadRequest('Bad signature')
