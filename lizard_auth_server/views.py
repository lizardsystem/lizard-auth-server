# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import urllib
import logging
from urlparse import urljoin

from django.conf.urls.defaults import patterns, url
from django.conf import settings
from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.views.generic.edit import FormView, FormMixin
from django.utils.translation import ugettext as _
from django.http import (
    HttpResponse,
    HttpResponseForbidden,
    HttpResponseBadRequest,
    HttpResponseRedirect
)
from django.utils import simplejson
from django.utils.decorators import method_decorator
from django.views.generic.base import View, TemplateView
from django.template.context import RequestContext
from django.template.response import TemplateResponse
from django.contrib.auth.models import User

from itsdangerous import URLSafeTimedSerializer, BadSignature
import pytz

from lizard_auth_server import forms
from lizard_auth_server.models import Token, Portal, UserProfile, Invitation
from lizard_auth_server.http import JsonResponse, JsonError
from lizard_auth_server.utils import SIMPLE_KEYS


logger = logging.getLogger(__name__)

TOKEN_TIMEOUT = datetime.timedelta(minutes=settings.SSO_TOKEN_TIMEOUT_MINUTES)

class ViewContextMixin(object):
    '''
    Adds the view object to the template context.

    Ensure this is first in the inheritance list!
    '''
    def get_context_data(self, **kwargs):
        return {
            'params': kwargs,
            'view': self
        }

class StaffOnlyMixin(object):
    '''
    Ensures access by staff members (user.is_staff is True) only to all
    HTTP methods.

    Ensure this is first in the inheritance list!
    '''
    @method_decorator(staff_member_required)
    def dispatch(self, request, *args, **kwargs):
        return super(StaffOnlyMixin, self).dispatch(request, *args, **kwargs)

class SecurePostMixin(object):
    '''
    Disable cache and strips passwords from debug-data.

    Ensure this is first in the inheritance list!
    '''
    @method_decorator(sensitive_post_parameters('password', 'old_password', 'new_password1', 'new_password2'))
    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        return super(SecurePostMixin, self).post(request, *args, **kwargs)

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

class ProfileView(ViewContextMixin, TemplateView):
    '''
    Straightforward view which displays a user's profile.
    '''
    template_name = 'lizard_auth_server/profile.html'
    _profile = None

    @property
    def profile(self):
        if not self._profile:
            self._profile = UserProfile.objects.fetch_for_user(self.request.user)
        return self._profile

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(ProfileView, self).dispatch(request, *args, **kwargs)

class ErrorMessageResponse(TemplateResponse):
    '''
    Display a slightly more user-friendly error message.
    '''
    def __init__(self, request, error_message=None, status=500):
        if not error_message:
            error_message = _('An unknown error occurred.')
        context = RequestContext(
            request,
            {
                'error_message': error_message
            }
        )
        super(ErrorMessageResponse, self).__init__(
            request,
            'lizard_auth_server/error_message.html',
            context,
            status=status
        )

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
            nextparams = urllib.urlencode([('next', '%s?%s' % (reverse('lizard_auth_server.sso_logout_redirect'), urllib.urlencode(nextparams)))])
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
        if self.request.user.is_staff:
            # staff can access any site
            return True
        # check whether the UserProfile object is related to this Portal
        profile = UserProfile.objects.fetch_for_user(self.request.user)
        return profile.portals.filter(pk=self.token.portal.pk).exists()

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
        params = urllib.urlencode([('next', '%s?%s' % (reverse('lizard_auth_server.sso_authorize'), urllib.urlencode(nextparams)))])
        return '%s?%s' % (reverse('django.contrib.auth.views.login'), params)

    def form_valid_unauthenticated(self):
        '''
        Redirect to login page when user isn't logged in yet.
        '''
        return HttpResponseRedirect(self.build_login_url())

def construct_user_data(user):
    '''
    Construct a dict of information about a user object,
    like first_name, permissions and organisation.
    '''
    data = {}
    for key in SIMPLE_KEYS:
        data[key] = getattr(user, key)
    data['permissions'] = []
    for perm in user.user_permissions.select_related('content_type').all():
        data['permissions'].append({
            'content_type': perm.content_type.natural_key(),
            'codename': perm.codename,
        })
    profile = UserProfile.objects.fetch_for_user(user)
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
        data = construct_user_data(self.token.user)
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

########################################
# Invitation / registration / activation
########################################

class InviteUserView(StaffOnlyMixin, SecurePostMixin, FormView):
    template_name = 'lizard_auth_server/register_user.html'
    form_class = forms.InviteUserForm

    def form_valid(self, form):
        data = form.cleaned_data

        # create and fill a new Invitation
        inv = Invitation()
        inv.name = data['name']
        inv.email = data['email']
        inv.language = data['language']
        inv.organisation = data['organisation']
        inv.save()

        # many-to-many, so save these after the invitation has been
        # assigned an ID
        inv.portals = data['portals']
        inv.save()

        inv.send_new_activation_email()

        return HttpResponseRedirect(reverse('lizard_auth_server.invite_user_complete', kwargs={'invitation_pk': inv.pk}))

class InviteUserCompleteView(StaffOnlyMixin, ViewContextMixin, TemplateView):
    template_name = 'lizard_auth_server/registration_complete.html'
    _invitiation = None

    def get(self, request, invitation_pk, *args, **kwargs):
        self.invitation_pk = int(invitation_pk)
        return super(InviteUserCompleteView, self).get(request, *args, **kwargs)

    @property
    def invitiation(self):
        if not self._invitiation:
            self._invitiation = Invitation.objects.get(pk=self.invitation_pk)
        return self._invitiation

class InvitationMixin(object):
    invitation = None

    def dispatch(self, request, activation_key, *args, **kwargs):
        try:
            self.invitation = Invitation.objects.get(activation_key=activation_key)
        except Invitation.DoesNotExist:
            return self.invalid_activation_key(request)
        return super(InvitationMixin, self).dispatch(request, *args, **kwargs)

    def invalid_activation_key(self, request):
        logger.warn('invalid activation key used by {}'.format(request.META['REMOTE_ADDR']))
        return ErrorMessageResponse(request, _('Invalid activation key. Perhaps this account was already activated?'), 404)

class ActivateUserView1(InvitationMixin, FormView):
    template_name = 'lizard_auth_server/activate_user.html'
    form_class = forms.ActivateUserForm1

    def get_initial(self):
        return {
            'email': self.invitation.email
        }

    def form_valid(self, form):
        data = form.cleaned_data

        # let the model handle the rest
        self.invitation.create_user(data)

        return HttpResponseRedirect(reverse('lizard_auth_server.activate_step_2', kwargs={'activation_key': self.invitation.activation_key}))

class ActivateUserView2(InvitationMixin, FormView):
    template_name = 'lizard_auth_server/activate_user_step_2.html'
    form_class = forms.ActivateUserForm2

    def form_valid(self, form):
        data = form.cleaned_data

        # let the model handle the rest
        self.invitation.activate(data)

        return HttpResponseRedirect(reverse('lizard_auth_server.activation_complete'))

class ActivationCompleteView(View):
    template_name = 'lizard_auth_server/activation_complete.html'
    _profile = None

    def get(self, request, profile_pk, *args, **kwargs):
        self.profile_pk = int(profile_pk)
        return super(ActivationCompleteView, self).get(request, *args, **kwargs)

    @property
    def profile(self):
        if not self._profile:
            self._profile = UserProfile.objects.get(pk=self.profile_pk)
        return self._profile

#######################
# APIs with minimal GUI
#######################

class AuthenticationApiView(FormView):
    '''
    View which can be used by API's to authenticate a
    username / password combo.
    '''
    form_class = forms.DecryptForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(AuthenticationApiView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        # just a simple debug form
        return HttpResponse(
            '''
            <form method="post">
            <input type="text" name="username">
            <input type="text" name="password">
            <input type="submit">
            </form>
            '''
        )

    @method_decorator(sensitive_post_parameters('password', 'old_password', 'new_password1', 'new_password2'))
    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        return super(FormView, self).post(request, *args, **kwargs)

    @method_decorator(sensitive_variables('password'))
    def form_valid(self, form):
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    return JsonError('User account is disabled.')
                else:
                    # TODO: check user access
                    user_data = construct_user_data(user)
                    return JsonResponse({'user': user_data})
            else:
                logger.warn('Login failed for user {} and ip {}'.format(username, self.request.META['REMOTE_ADDR']))
                return JsonError('Login failed')
        else:
            return JsonError('Missing "username" or "password" POST parameters.')

    def form_invalid(self, form):
        logger.error('Error while decrypting form: {}'.format(form.errors.as_text()))
        return HttpResponseBadRequest('Bad signature')
