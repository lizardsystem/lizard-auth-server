# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from django.contrib.auth import authenticate as django_authenticate
from django.contrib.auth.models import User
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
)
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.debug import sensitive_variables
from django.views.generic.edit import FormView

from lizard_auth_server import forms
from lizard_auth_server.http import JsonError, JsonResponse
from lizard_auth_server.models import UserProfile
from lizard_auth_server.views_sso import construct_user_data

logger = logging.getLogger(__name__)


class AuthenticateUnsignedView(FormView):
    '''
    View which can be used by API's to authenticate a
    username / password combo.
    Unsigned edition, so it can be used from GeoServer.
    '''
    form_class = forms.AuthenticateUnsignedForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(AuthenticateUnsignedView, self).dispatch(
            request, *args, **kwargs
        )

    def get(self, request, *args, **kwargs):
        # just a simple debug form
        return HttpResponse(
            '''
            <form method="post">
            <input type="text" name="key">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit">
            </form>
            '''
        )

    @method_decorator(sensitive_post_parameters(
        'password', 'old_password', 'new_password1', 'new_password2'
    ))
    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        return super(FormView, self).post(request, *args, **kwargs)

    @method_decorator(sensitive_variables('password'))
    def form_valid(self, form):
        portal = form.portal
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')

        if username and password:
            return self.authenticate(portal, username, password)
        else:
            return JsonError(
                'Missing "username" or "password" POST parameters.'
            )

    def form_invalid(self, form):
        logger.error('Error in posted form: {}'.format(form.errors.as_text()))
        return HttpResponseBadRequest('Bad input')

    @method_decorator(sensitive_variables('password'))
    def authenticate(self, portal, username, password):
        user = django_authenticate(username=username, password=password)
        if user:
            if not user.is_active:
                return JsonError('User account is disabled')
            else:
                try:
                    profile = user.get_profile()
                except UserProfile.DoesNotExist:
                    return JsonError('No access to this portal')
                if profile.has_access(portal):
                    user_data = construct_user_data(profile=profile)
                    return JsonResponse({'user': user_data})
                else:
                    return JsonError('No access to this portal')
        else:
            logger.warn('Login failed for user {} and ip {}'.format(
                username, self.request.META['REMOTE_ADDR']
            ))
            return JsonError('Login failed')


class AuthenticateView(FormView):
    '''
    View which can be used by API's to authenticate a
    username / password combo.
    '''
    form_class = forms.DecryptForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(AuthenticateView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        # just a simple debug form
        return HttpResponse(
            '''
            <form method="post">
            <input type="text" name="username">
            <input type="password" name="password">
            <input type="submit">
            </form>
            '''
        )

    @method_decorator(sensitive_post_parameters(
        'password', 'old_password', 'new_password1', 'new_password2'
    ))
    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        return super(FormView, self).post(request, *args, **kwargs)

    @method_decorator(sensitive_variables('password'))
    def form_valid(self, form):
        portal = form.portal
        username = form.cleaned_data.get('username')
        password = form.cleaned_data.get('password')

        if username and password:
            return self.authenticate(portal, username, password)
        else:
            return JsonError(
                'Missing "username" or "password" POST parameters.'
            )

    def form_invalid(self, form):
        logger.error('Error while decrypting form: {}'.format(
            form.errors.as_text()
        ))
        return HttpResponseBadRequest('Bad signature')

    @method_decorator(sensitive_variables('password'))
    def authenticate(self, portal, username, password):
        user = django_authenticate(username=username, password=password)
        if user:
            if not user.is_active:
                return JsonError('User account is disabled')
            else:
                try:
                    profile = user.get_profile()
                except UserProfile.DoesNotExist:
                    return JsonError('No access to this portal')
                if profile.has_access(portal):
                    user_data = construct_user_data(profile=profile)
                    return JsonResponse({'user': user_data})
                else:
                    return JsonError('No access to this portal')
        else:
            logger.warn('Login failed for user {} and ip {}'.format(
                username, self.request.META['REMOTE_ADDR']
            ))
            return JsonError('Login failed')


class GetUserView(FormView):
    '''
    View which can be used by API's to fetch user data.
    '''
    form_class = forms.DecryptForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(GetUserView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        # just a simple debug form
        return HttpResponse(
            '''
            <form method="post">
            <input type="text" name="username">
            <input type="submit">
            </form>
            '''
        )

    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        return super(FormView, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        portal = form.portal
        username = form.cleaned_data.get('username')

        if username:
            return self.get_user(portal, username)
        else:
            return JsonError('Missing "username" POST parameter.')

    def form_invalid(self, form):
        logger.error('Error while decrypting form: {}'.format(
            form.errors.as_text()
        ))
        return HttpResponseBadRequest('Bad signature')

    def get_user(self, portal, username):
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            user = None
        if user:
            if not user.is_active:
                return JsonError('User account is disabled')
            else:
                try:
                    profile = user.get_profile()
                except UserProfile.DoesNotExist:
                    return JsonError('No access to this portal')
                if profile.has_access(portal):
                    user_data = construct_user_data(profile=profile)
                    return JsonResponse({'user': user_data})
                else:
                    return JsonError('No access to this portal')
        else:
            return JsonError(
                'No such user. ' +
                'Perhaps you need to add user to the SSO server first?'
            )


class GetUsersView(FormView):
    '''
    View which can be used by API's to fetch all users of a portal.
    '''
    form_class = forms.DecryptForm

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(GetUsersView, self).dispatch(request, *args, **kwargs)

    @method_decorator(never_cache)
    def post(self, request, *args, **kwargs):
        return super(FormView, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        return self.get_users(form.portal)

    def form_invalid(self, form):
        logger.error(
            'Error while decrypting form: {}'.format(form.errors.as_text())
        )
        return HttpResponseBadRequest('Bad signature')

    def get_users(self, portal):
        user_data = []
        for user in User.objects.select_related('userprofile'):
            try:
                profile = user.get_profile()
            except UserProfile.DoesNotExist:
                continue
            if profile.has_access(portal):
                user_data.append(construct_user_data(profile=profile))
        return JsonResponse({'users': user_data})
