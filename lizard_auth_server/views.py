# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import urllib
import logging
from urlparse import urljoin

from django.conf.urls.defaults import patterns, url
from django.conf import settings
from django.core.urlresolvers import reverse
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.debug import sensitive_post_parameters, sensitive_variables
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect, csrf_exempt
from django.views.generic.edit import FormView, FormMixin
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
    Ensure this is first in the inheritance list!
    '''
    def get_context_data(self, **kwargs):
        return {
            'params': kwargs,
            'view': self
        }

class StaffOnlyMixin(object):
    '''
    Ensure this is first in the inheritance list!
    '''
    @method_decorator(staff_member_required)
    def dispatch(self, request, *args, **kwargs):
        return super(StaffOnlyMixin, self).dispatch(request, *args, **kwargs)

class SecurePostMixin(object):
    '''
    Ensure this is first in the inheritance list!
    '''
    @method_decorator(sensitive_post_parameters('password', 'old_password', 'new_password1', 'new_password2'))
    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        return super(SecurePostMixin, self).post(request, *args, **kwargs)

class ProcessGetFormView(FormMixin, View):
    def get_form(self, form_class):
        return form_class(self.request.GET)

    def get(self, request, *args, **kwargs):
        form_class = self.get_form_class()
        form = self.get_form(form_class)
        if form.is_valid():
            return self.form_valid(form)
        else:
            return self.form_invalid(form)

class ProfileView(ViewContextMixin, TemplateView):
    template_name = 'lizard_auth_server/profile.html'
    _profile = None

    def profile(self):
        if not self._profile:
            self._profile = UserProfile.objects.fetch_for_user(self.request.user)
        return self._profile

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(ProfileView, self).dispatch(request, *args, **kwargs)

class PortalActionView(ProcessGetFormView):
    '''
    View that either redirects to the actual logout page,
    or back to the portal.
    '''
    form_class = forms.DecryptForm

    def form_valid(self, form):
        portal = form.portal
        if form.cleaned_data['action'] == 'logout':
            nextparams = {
                'message': self.request.GET['message'],
                'key': self.request.GET['key'],
            }
            nextparams = urllib.urlencode([('next', '%s?%s' % (reverse('lizard_auth_server.sso_logout_redirect'), urllib.urlencode(nextparams)))])
            url = '%s?%s' % (reverse('django.contrib.auth.views.logout'), nextparams)
            return HttpResponseRedirect(url)
        else:
            return HttpResponseBadRequest('Unknown action')

    def form_invalid(self, form):
        logger.error('Error while while decrypting form: {}'.format(form.errors.as_text()))
        import pdb; pdb.set_trace()
        return HttpResponseBadRequest('Bad signature')

class LogoutRedirectView(View):
    '''
    View that either redirects to the actual logout page,
    or back to the SSO client.
    '''
    def get(self, request):
        decrypted = forms.DecryptForm(request.GET)
        if decrypted.is_valid():
            self.portal = decrypted.portal
            if decrypted.cleaned_data['action'] == 'logout':
                url = urljoin(self.portal.redirect_url, 'sso/local_logout') + '/'
                return HttpResponseRedirect(url)
            else:
                return HttpResponseBadRequest('Unknown action')
        else:
            return HttpResponseBadRequest('Bad signature')

class PermissionDeniedView(TemplateView):
    template_name = '403.html'

class RequestTokenView(View):
    """
    Request Token Request view called by the portal application to obtain a
    one-time Request Token.
    """
    def get(self, request):
        self.form = forms.DecryptForm(request.GET)
        if self.form.is_valid():
            self.portal = self.form.portal
            return self.form_valid()
        else:
            return self.form_invalid()
    
    def get_token(self):
        return Token.objects.create_for_portal(self.portal)
    
    def form_valid(self):
        token = self.get_token()
        params = {
            'request_token': token.request_token
        }
        data = URLSafeTimedSerializer(token.portal.sso_secret).dumps(params)
        return HttpResponse(data)
    
    def form_invalid(self, form):
        logger.error('Error while while decrypting form: {}'.format(form.errors.as_text()))
        return HttpResponseBadRequest('Bad signature')

class AuthorizeView(View):
    """
    The portal get's redirected to this view with the `request_token` obtained
    by the Request Token Request by the portal application beforehand.
    
    This view checks if the user is logged in on the server application and if
    that user has the necessary rights.
    
    If the user is not logged in, the user is prompted to log in.
    """
    @method_decorator(never_cache)
    def get(self, request):
        decrypted = forms.DecryptForm(request.GET)
        if decrypted.is_valid():
            self.portal = decrypted.portal
            request_token = decrypted.cleaned_data['request_token']
            try:
                self.token = Token.objects.get(request_token=request_token, portal=self.portal, user__isnull=True)
            except Token.DoesNotExist:
                raise Exception('Invalid request token')
            if self.check_token_timeout():
                return self.form_valid()
            else:
                return self.token_timeout()
        else:
            return self.form_invalid()
        
    def form_valid(self):
        if self.request.user.is_authenticated():
            return self.form_valid_authenticated()
        else:
            return self.form_valid_unauthenticated()

    def check_token_timeout(self):
        delta = datetime.datetime.now(tz=pytz.UTC) - self.token.created
        return delta <= TOKEN_TIMEOUT
    
    def token_timeout(self):
        self.token.delete()
        return HttpResponseForbidden('Token timed out')
    
    def form_valid_authenticated(self):
        if self.has_access():
            return self.success()
        else:
            return self.access_denied()
        
    def has_access(self):
        '''check whether the user has access to the portal'''
        if not self.request.user.is_active:
            # extra check: should not be necessary as inactive users can't
            # login anyway
            return False
        if self.request.user.is_staff:
            # staff can access any site
            return True
        profile = UserProfile.objects.fetch_for_user(self.request.user)
        return profile.portals.filter(pk=self.token.portal.pk).exists()
    
    def success(self):
        url = urljoin(self.token.portal.redirect_url, 'sso/local_login') + '/'
        params = {
            'request_token': self.token.request_token,
            'auth_token': self.token.auth_token
        }
        message = URLSafeTimedSerializer(self.token.portal.sso_secret).dumps(params)
        self.token.user = self.request.user
        self.token.save()
        url = '%s?%s' % (url, urllib.urlencode({'message': message}))
        return HttpResponseRedirect(url)
    
    def access_denied(self):
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
        '''store the authorize view (most likely the current view) as "next" page for a login page'''
        nextparams = {
            'message': self.request.GET['message'],
            'key': self.request.GET['key'],
        }
        params = urllib.urlencode([('next', '%s?%s' % (reverse('lizard_auth_server.sso_authorize'), urllib.urlencode(nextparams)))])
        return '%s?%s' % (reverse('django.contrib.auth.views.login'), params)
    
    def form_valid_unauthenticated(self):
        '''redirect to login page'''
        return HttpResponseRedirect(self.build_login_url())
        
    def form_invalid(self):
        return HttpResponseBadRequest('Bad signature')

def construct_user_data(user):
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
        data[key] = getattr(profile, key)
    for key in ['created_at']:
        # datetimes should be serialized to an iso8601 string
        data[key] = getattr(profile, key).isoformat()
    return data

class VerifyView(View):
    """
    View called by the portal application to verify the Auth Token passed by
    the portal request as GET parameter with the server application
    """
    def get(self, request):
        decrypted = forms.DecryptForm(request.GET)
        if decrypted.is_valid():
            self.portal = decrypted.portal
            auth_token = decrypted.cleaned_data['auth_token']
            try:
                self.token = Token.objects.get(auth_token=auth_token, user__isnull=False, portal=self.portal)
            except Token.DoesNotExist:
                raise Exception('Invalid auth token')
            return self.form_valid()
        else:
            return self.form_invalid()

    def get_user_json(self):
        """
        Returns the JSON string representation of the user object for a portal.
        """
        data = construct_user_data(self.token.user)
        return simplejson.dumps(data)
    
    def form_valid(self):
        user_data = self.get_user_json()
        params = {
            'user': user_data
        }
        data = URLSafeTimedSerializer(self.token.portal.sso_secret).dumps(params)
        self.token.delete()
        return HttpResponse(data)
        
    def form_invalid(self):
        return HttpResponseBadRequest('Bad signature')

########################################
# Invitation / registration / activation
########################################

class InviteUserView(StaffOnlyMixin, SecurePostMixin, FormView):
    template_name = 'lizard_auth_server/register_user.html'
    form_class = forms.InviteUserForm

    def form_valid(self, form):
        data = form.cleaned_data
#        inv = Invitation()
#        inv.name = data['name']
#        inv.email = data['email']
#        inv.language = data['language']
#        inv.organisation = data['organisation']
#        inv.save()
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

#        inv.portals = data['portals']

        inv.send_new_activation_email()

        return HttpResponseRedirect(reverse('lizard_auth_server.invite_user_complete', kwargs={'invitation_pk': inv.pk}))

class InviteUserCompleteView(StaffOnlyMixin, ViewContextMixin, TemplateView):
    template_name = 'lizard_auth_server/registration_complete.html'
    _invitiation = None

    def get(self, request, invitation_pk, *args, **kwargs):
        self.invitation_pk = int(invitation_pk)
        return super(InviteUserCompleteView, self).get(request, *args, **kwargs)

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
            return self.invalid_activation_key()
        return super(InvitationMixin, self).dispatch(request, *args, **kwargs)

    def invalid_activation_key(self):
        return HttpResponseBadRequest('Invalid activation key')

class ActivateUserView1(InvitationMixin, FormView):
    template_name = 'lizard_auth_server/activate_user.html'
    form_class = forms.ActivateUserForm1

    def get_initial(self):
        return {
            'email': self.invitation.email
        }

    def form_valid(self, form):
        data = form.cleaned_data

        self.invitation.create_user(data)

        return HttpResponseRedirect(reverse('lizard_auth_server.activate_step_2', kwargs={'activation_key': self.invitation.activation_key}))

class ActivateUserView2(InvitationMixin, FormView):
    template_name = 'lizard_auth_server/activate_user_step_2.html'
    form_class = forms.ActivateUserForm2

    def form_valid(self, form):
        data = form.cleaned_data

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

class AuthenticationApiView(SecurePostMixin, View):
    '''
    View which can be used by API's to authenticate a username / password combo.
    '''

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

    @method_decorator(sensitive_variables('password'))
    def post(self, request, *args, **kwargs):
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    return JsonError('User account is disabled.')
                else:
                    data = construct_user_data(user)
                    return JsonResponse(data)
            else:
                return JsonError('Login failed')
        else:
            return JsonError('Missing "username" or "password" POST parameters.')
