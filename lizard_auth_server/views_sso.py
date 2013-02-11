# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import urllib
import logging
from urlparse import urljoin

from django.conf import settings
from django.core.urlresolvers import reverse
from django.views.decorators.cache import never_cache
from django.views.generic.edit import FormMixin
from django.utils.translation import ugettext as _
from django.http import (
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseBadRequest,
    HttpResponseRedirect
)
from django.utils import simplejson
from django.utils.decorators import method_decorator
from django.views.generic.base import View
from django.template.context import RequestContext
from django.template.response import TemplateResponse

from itsdangerous import URLSafeTimedSerializer
import pytz

from lizard_auth_server import forms
from lizard_auth_server.models import Token
from lizard_auth_server.utils import SIMPLE_KEYS
from lizard_auth_server.views import ErrorMessageResponse

logger = logging.getLogger(__name__)

TOKEN_TIMEOUT = datetime.timedelta(minutes=settings.SSO_TOKEN_TIMEOUT_MINUTES)

class ProcessGetFormView(FormMixin, View):
    '''
    A view which validates a form using GET parameters
    instead of POST.

    See Django's ProcessFormView.
    '''
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
    '''
    View that allows portals to do some miscellaneous actions,
    like logging out.
    '''
    form_class = forms.DecryptForm

    def form_valid(self, form):
        portal = form.portal
        if form.cleaned_data['action'] == 'logout':
            nextparams = {
                'message': self.request.GET['message'],
                'key': self.request.GET['key'],
            }
            # after logout, redirect user to the LogoutRedirectView,
            # which should redirect the user back to the portal again.
            nextparams = urllib.urlencode([('next', '%s?%s' % (reverse('lizard_auth_server.sso.logout_redirect'), urllib.urlencode(nextparams)))])
            url = '%s?%s' % (reverse('django.contrib.auth.views.logout'), nextparams)
            return HttpResponseRedirect(url)
        else:
            return HttpResponseBadRequest('Unknown action')

    def form_invalid(self, form):
        logger.error('Error while decrypting form: {}'.format(form.errors.as_text()))
        return ErrorMessageResponse(self.request, _('Communication error.'), 400)

class LogoutRedirectView(ProcessGetFormView):
    '''
    View that redirects the user to the logout page of the portal.
    '''
    form_class = forms.DecryptForm

    def form_valid(self, form):
        if form.cleaned_data['action'] == 'logout':
            url = urljoin(form.portal.redirect_url, 'sso/local_logout') + '/'
            return HttpResponseRedirect(url)
        else:
            return HttpResponseBadRequest('Unknown action')

    def form_invalid(self, form):
        logger.error('Error while decrypting form: {}'.format(form.errors.as_text()))
        return ErrorMessageResponse(self.request, _('Communication error.'), 400)

class RequestTokenView(ProcessGetFormView):
    '''
    Request Token Request view called by the portal application to obtain a
    one-time Request Token.
    '''
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
        logger.error('Error while decrypting form: {}'.format(form.errors.as_text()))
        return HttpResponseBadRequest('Bad signature')

class AuthorizeView(ProcessGetFormView):
    '''
    The portal get's redirected to this view with the `request_token` obtained
    by the Request Token Request by the portal application beforehand.

    This view checks if the user is logged in on the server application and if
    that user has the necessary rights.

    If the user is not logged in, the user is prompted to log in.
    '''
    form_class = forms.DecryptForm

    def form_valid(self, form):
        request_token = form.cleaned_data['request_token']
        try:
            self.token = Token.objects.get(request_token=request_token, portal=form.portal, user__isnull=True)
        except Token.DoesNotExist:
            return HttpResponseForbidden('Invalid request token')
        if self.check_token_timeout():
            if self.request.user.is_authenticated():
                return self.form_valid_authenticated()
            else:
                return self.form_valid_unauthenticated()
        else:
            return self.token_timeout()

    def form_invalid(self, form):
        logger.error('Error while decrypting form: {}'.format(form.errors.as_text()))
        return ErrorMessageResponse(self.request, _('Communication error.'), 400)

    def check_token_timeout(self):
        delta = datetime.datetime.now(tz=pytz.UTC) - self.token.created
        return delta <= TOKEN_TIMEOUT

    def token_timeout(self):
        self.token.delete()
        return ErrorMessageResponse(self.request, _('Token timed out. Please return to the portal to get a fresh token.'), 403)

    def form_valid_authenticated(self):
        '''
        Called then login succeeded.
        '''
        if self.has_access():
            return self.success()
        else:
            return self.access_denied()

    def has_access(self):
        '''
        Check whether the user has access to the portal.
        '''
        if not self.request.user.is_active:
            # extra check: should not be necessary as inactive users can't
            # login anyway
            return False
        # check whether the UserProfile object is related to this Portal
        profile = self.request.user.get_profile()
        return profile.has_access(self.token.portal)

    def success(self):
        params = {
            'request_token': self.token.request_token,
            'auth_token': self.token.auth_token
        }
        # encrypt the tokens with the secret key of the portal
        message = URLSafeTimedSerializer(self.token.portal.sso_secret).dumps(params)
        # link the user model to the token model, so we can return the
        # proper profile when the SSO client calls the VerifyView
        self.token.user = self.request.user
        self.token.save()
        # redirect user back to the portal
        url = urljoin(self.token.portal.redirect_url, 'sso/local_login') + '/'
        url = '%s?%s' % (url, urllib.urlencode({'message': message}))
        return HttpResponseRedirect(url)

    def access_denied(self):
        '''
        Show a user-friendly access denied page.
        '''
        context = RequestContext(
            self.request,
            {
                'login_url': self.build_login_url()
            }
        )
        return TemplateResponse(
            self.request,
            'lizard_auth_server/access_denied.html',
            context,
            status=403
        )

    def build_login_url(self):
        '''
        Store the authorize view (most likely the current view) as
        "next" page for a login page.
        '''
        nextparams = {
            'message': self.request.GET['message'],
            'key': self.request.GET['key'],
        }
        params = urllib.urlencode([('next', '%s?%s' % (reverse('lizard_auth_server.sso.authorize'), urllib.urlencode(nextparams)))])
        return '%s?%s' % (reverse('django.contrib.auth.views.login'), params)

    def form_valid_unauthenticated(self):
        '''
        Redirect to login page when user isn't logged in yet.
        '''
        return HttpResponseRedirect(self.build_login_url())

def construct_user_data(user=None, profile=None):
    '''
    Construct a dict of information about a user object,
    like first_name, permissions and organisation.
    '''
    if user is None:
        user = profile.user
    if profile is None:
        profile = user.get_profile()
    data = {}
    for key in SIMPLE_KEYS:
        data[key] = getattr(user, key)
    data['permissions'] = []
    for perm in user.user_permissions.select_related('content_type').all():
        data['permissions'].append({
            'content_type': perm.content_type.natural_key(),
            'codename': perm.codename,
        })
    for key in ['organisation']:
        # copy the profile data, not sure how much more we want to add
        data[key] = getattr(profile, key)
    for key in ['created_at']:
        # datetimes should be serialized to an iso8601 string
        data[key] = getattr(profile, key).isoformat()
    return data

class VerifyView(ProcessGetFormView):
    '''
    View called by the portal application to verify the Auth Token passed by
    the portal request as GET parameter with the server application
    '''
    form_class = forms.DecryptForm

    def get_user_json(self):
        '''
        Returns the JSON string representation of the user object for a portal.
        '''
        profile = self.token.user.get_profile()
        data = construct_user_data(profile=profile)
        return simplejson.dumps(data)

    def form_valid(self, form):
        auth_token = form.cleaned_data['auth_token']
        try:
            self.token = Token.objects.get(auth_token=auth_token, user__isnull=False, portal=form.portal)
        except Token.DoesNotExist:
            return HttpResponseForbidden('Invalid auth token')
        # get some metadata about the user, so we can construct a user on the
        # SSO client
        user_json = self.get_user_json()
        params = {
            'user': user_json
        }
        # encrypt the data
        data = URLSafeTimedSerializer(self.token.portal.sso_secret).dumps(params)
        # disable the token
        self.token.delete()
        return HttpResponse(data)

    def form_invalid(self, form):
        logger.error('Error while decrypting form: {}'.format(form.errors.as_text()))
        return HttpResponseBadRequest('Bad signature')
