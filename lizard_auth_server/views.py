# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import datetime
import urllib
from urlparse import urljoin

from django.conf.urls.defaults import patterns, url
from django.conf import settings
from django.core.urlresolvers import reverse
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.generic.edit import FormView
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

from itsdangerous import URLSafeTimedSerializer, BadSignature

from lizard_auth_server import forms
from lizard_auth_server.models import Token, Portal, UserProfile

from lizard_auth_server.utils import SIMPLE_KEYS


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
    #@method_decorator(sensitive_post_parameters) # Causes an error?
    @method_decorator(csrf_protect)
    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        return super(SecurePostMixin, self).post(request, *args, **kwargs)

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

class PortalActionView(View):
    '''
    View that either redirects to the actual logout page,
    or back to the SSO client.
    '''
    def get(self, request):
        decrypted = forms.DecryptForm(request.GET)
        if decrypted.is_valid():
            self.portal = decrypted.portal
            if decrypted.cleaned_data['action'] == 'logout':
                nextparams = {
                    'message': self.request.GET['message'],
                    'key': self.request.GET['key'],
                }
                nextparams = urllib.urlencode([('next', '%s?%s' % (reverse('lizard_auth_server.sso_logout_redirect'), urllib.urlencode(nextparams)))])
                url = '%s?%s' % (reverse('django.contrib.auth.views.logout'), nextparams)
                return HttpResponseRedirect(url)
            else:
                return HttpResponseBadRequest('Unknown action')
        else:
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
        decrypted = forms.DecryptForm(request.GET)
        if decrypted.is_valid():
            self.portal = decrypted.portal
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
    
    def form_invalid(self):
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
        delta = datetime.datetime.now() - self.token.created
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
    
    def construct_user(self):
        data = {}
        for key in SIMPLE_KEYS:
            data[key] = getattr(self.token.user, key)
        data['permissions'] = []
        for perm in self.token.user.user_permissions.select_related('content_type').all():
            data['permissions'].append({
                'content_type': perm.content_type.natural_key(),
                'codename': perm.codename,
            })
        return data

    def get_user_json(self):
        """
        Returns the JSON string representation of the user object for a portal.
        """
        data = self.construct_user()
        return simplejson.dumps(data)
    
    def form_valid(self):
        self.user = self.get_user_json()
        params = {
            'user': self.user
        }
        data = URLSafeTimedSerializer(self.token.portal.sso_secret).dumps(params)
        self.token.delete()
        return HttpResponse(data)
        
    def form_invalid(self):
        return HttpResponseBadRequest('Bad signature')

class RegisterUserView(StaffOnlyMixin, SecurePostMixin, FormView):
    template_name = 'lizard_auth_server/register_user.html'
    form_class = forms.RegisterUserForm

    def form_valid(self, form):
        data = form.cleaned_data
        profile = UserProfile.objects.create_deactivated(
            data['name'],
            data['email'],
            data['language'],
            data['organisation'],
            data['portals']
        )
        profile.send_new_activation_email()
        return HttpResponseRedirect(reverse('lizard_auth_server.registration_complete', kwargs={'profile_pk': profile.pk}))

class RegistrationCompleteView(StaffOnlyMixin, ViewContextMixin, TemplateView):
    template_name = 'lizard_auth_server/registration_complete.html'
    _registered_profile = None

    def get(self, request, profile_pk, *args, **kwargs):
        self.profile_pk = int(profile_pk)
        return super(RegistrationCompleteView, self).get(request, *args, **kwargs)

    def registered_profile(self):
        if not self._registered_profile:
            self._registered_profile = UserProfile.objects.get(pk=self.profile_pk)
        return self._registered_profile

class ActivationMixin(object):
    activation_key = None
    activation_profile = None

    def dispatch(self, request, activation_key, *args, **kwargs):
        self.activation_key = activation_key
        try:
            self.activation_profile = UserProfile.objects.get(activation_key=activation_key)
        except UserProfile.NotFound:
            self.invalid_activation_key()
        return super(ActivationMixin, self).dispatch(request, *args, **kwargs)

    def invalid_activation_key(self):
        return HttpResponseBadRequest('Invalid activation key')

class ActivateUserView1(ActivationMixin, FormView):
    template_name = 'lizard_auth_server/activate_user.html'
    form_class = forms.ActivateUserForm1

    def form_valid(self, form):
        data = form.cleaned_data
        return HttpResponseRedirect(reverse('lizard_auth_server.activate_step_2', kwargs={'activation_key': self.activation_key}))

class ActivateUserView2(ActivationMixin, FormView):
    template_name = 'lizard_auth_server/activate_user_step_2.html'
    form_class = forms.ActivateUserForm2

    def get_initial(self):
        return {
            'email': self.activation_profile.activation_email
        }

    def form_valid(self, form):
        data = form.cleaned_data
        return HttpResponseRedirect(reverse('lizard_auth_server.activation_complete'))

class ActivationCompleteView(FormView):
    pass
