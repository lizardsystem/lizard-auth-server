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
from django.forms import ValidationError
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import View
from django.views.generic.edit import FormMixin
from django.views.generic.edit import ProcessFormView
import jwt

from lizard_auth_server import forms
from lizard_auth_server.models import Portal
from lizard_auth_server.views_sso import FormInvalidMixin
from lizard_auth_server.views_sso import ProcessGetFormView
from lizard_auth_server.views_sso import domain_match


logger = logging.getLogger(__name__)

JWT_EXPIRATION = datetime.timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
JWT_ALGORITHM = settings.LIZARD_AUTH_SERVER_JWT_ALGORITHM

LOGIN_SUCCESS_URL_KEY = 'login_success_url'
UNAUTHENTICATED_IS_OK_URL_KEY = 'unauthenticated_is_ok_url'


# Copied from views_sso.py
def construct_user_data(user=None, user_profile=None):
    """Return dict with user data

    The returned keys are the bare minimum: username, first_name, last_name
    and email. No permissions or is_superuser flags!

    """
    if user is None:
        user = user_profile.user
    if user_profile is None:
        user_profile = user.user_profile
    user_data = {}
    for key in ['username', 'first_name', 'last_name', 'email']:
        user_data[key] = getattr(user, key)
    return user_data


class StartView(View):
    """V2 API startpoint that lists the available endpoints.

    This discouples lizard-auth-client from lizard-auth-server by removing
    hardcoded URLs from lizard-auth-client. You only need to specify the url
    of this startview.

    """

    def get(self, request):
        """Return available endpoints

        The available endpoints:

        - ``check-credentials``: :class:`lizard_auth_server.views_api_v2.CheckCredentialsView`

        - ``login``: :class:`lizard_auth_server.views_api_v2.LoginView`

        - ``logout``: :class:`lizard_auth_server.views_api_v2.LogoutView`

        Returns: json dict with available endpoints

        """
        endpoints = {
            'check-credentials':
            reverse('lizard_auth_server.api_v2.check_credentials'),
            'login': reverse('lizard_auth_server.api_v2.login'),
            'logout': reverse('lizard_auth_server.api_v2.logout'),
        }
        return HttpResponse(json.dumps(endpoints),
                            content_type='application/json')


class LoginView(FormInvalidMixin, ProcessGetFormView):
    form_class = forms.JWTDecryptForm

    def form_valid(self, form):
        """Handle the successfully decoded and verified JWT message.

        The JWT message's content is now the form's cleaned data. So we start
        out by extracting the contents. Then depending on whether the user is
        authenticated, we call :meth:`.form_valid_and_authenticated` or
        :meth:`.form_valid_but_unauthenticated`.

        Args:
            form: A :class:`lizard_auth_server.forms.JWTDecryptForm`
                instance. It will have the JWT message contents in the
                ``cleaned_data`` attribute. ``login_success_url`` is mandatory
                in the message. ``unauthenticated_is_ok_url`` is
                optional. When present, if unauthenticated, the user is
                redirected back to the site without being forced to log in.

        Raises:
            ValidationError: when necessary keys are missing from the decoded
                JWT message.

        """
        # Extract data from the JWT message including validation.
        self.portal = Portal.objects.get(sso_key=form.cleaned_data['iss'])
        if not LOGIN_SUCCESS_URL_KEY in form.cleaned_data:
            raise ValidationError(
                "Mandatory key '%s' is missing from JWT message" %
                LOGIN_SUCCESS_URL_KEY)
        self.login_success_url = form.cleaned_data[LOGIN_SUCCESS_URL_KEY]
        self.unauthenticated_is_ok_url = form.cleaned_data.get(
            UNAUTHENTICATED_IS_OK_URL_KEY)

        # Handle the form.
        if self.request.user.is_authenticated():
            return self.form_valid_and_authenticated()
        return self.form_valid_but_unauthenticated()

    def our_login_page_url(self):
        """Return our own login page with the current view as 'next' page.

        The current view is passed as the 'next' parameter, including the
        original key and message.
        """
        nextparams = {'message': self.request.GET['message'],
                      'key': self.request.GET['key']}
        params = urlencode([(
            'next',
            '%s?%s' % (
                reverse('lizard_auth_server.api_v2.login'),
                urlencode(nextparams))
        )])
        return '%s?%s' % (reverse('django.contrib.auth.views.login'), params)

    def form_valid_but_unauthenticated(self):
        """Handle user login

        Normally, redirect the user to our login page.

        Alternatively, when an ``unauthenticated_is_ok_url`` has been passed
        in the JWT message, redirect back to that url. This way a site can do
        a "soft login": *if* a user is already authenticated, profit from
        that. *If not*, don't force them to log in.

        """
        if not self.unauthenticated_is_ok_url:
            return HttpResponseRedirect(self.our_login_page_url())
        else:
            return HttpResponseRedirect(self.unauthenticated_is_ok_url)

    def form_valid_and_authenticated(self):
        """Return authenticated user (called when login succeeded)"""
        payload = {
            # JWT fields (intended audience + expiration datetime)
            'aud': self.portal.sso_key,
            'exp': datetime.datetime.utcnow() + JWT_EXPIRATION,
            # Dump all relevant data:
            'user': json.dumps(construct_user_data(self.request.user)),
            }
        signed_message = jwt.encode(payload,
                                    self.portal.sso_secret,
                                    algorithm=JWT_ALGORITHM)
        params = {'message': signed_message}
        url_with_params = '%s?%s' % (self.login_success_url, urlencode(params))
        return HttpResponseRedirect(url_with_params)


class CheckCredentialsView(FormInvalidMixin, FormMixin, ProcessFormView):
    """View to simply verify credentials, used by APIs.

    A username+password is passed in a JWT signed form (so: in plain text). We
    verify if the password is OK and whether the user has access to the
    portal. No redirects to forms, just a '200 OK' when the credentials are OK
    and an error code if not.

    Only POST is allowed as otherwise the web server's access log would show
    the GET parameter with the plain encoded password.

    """
    form_class = forms.JWTDecryptForm
    http_method_names = ['post']

    @method_decorator(csrf_exempt)
    def dispatch(self, request, *args, **kwargs):
        return super(CheckCredentialsView, self).dispatch(
            request, *args, **kwargs)

    @method_decorator(sensitive_post_parameters('message'))
    def post(self, request, *args, **kwargs):
        return super(CheckCredentialsView, self).post(request, *args, **kwargs)

    def form_valid(self, form):
        """Return user data when credentials are valid

        The JWT message's content is now the form's cleaned data. So we start
        out by extracting the contents. Then we check the credentials.

        Args:
            form: A :class:`lizard_auth_server.forms.JWTDecryptForm`
                instance. It will have the JWT message contents in the
                ``cleaned_data`` attribute. ``username`` and ``password`` are
                mandatory keys in the message.

        Returns:
            A dict with key ``user`` with user data like first name, last
            name.

        Raises:
            PermissionDenied: when the username/password combo is invalid.

            ValidationError: when username and/or password keys are missing
                from the decoded JWT message.

        """
        # The JWT message is validated; now check the message's contents.
        if ((not 'username' in form.cleaned_data) or
            (not 'password' in form.cleaned_data)):
            raise ValidationError(
                "username and/or password are missing from the JWT message")
        # Verify the username/password
        user = django_authenticate(username=form.cleaned_data.get('username'),
                                   password=form.cleaned_data.get('password'))
        if not user:
            raise PermissionDenied("Login failed")

        user_data = construct_user_data(user=user)
        return HttpResponse(json.dumps({'user': user_data}),
                            content_type='application/json')


class LogoutView(FormInvalidMixin, ProcessGetFormView):
    """Initial view for logging out.

    Logging out means logging out on both the SSO (=us) and being redirected
    back to the corresponding logout page on the portal.

    So the start is this
    :class:`lizard_auth_server.views_api_v2.LogoutView`. It prepares a
    ``next`` url and redirects the user to Django's own logout view, passing
    the ``next`` url as a parameter.

    Django's logout view does the actual logging-out on the SSO. Afterwards,
    it redirects to the url in the ``next`` parameter.

    The ``next`` url is third: the
    :class:`lizard_auth_server.views_api_v2.LogoutRedirectView`. It redirects
    the user back to the portal (actually: to the logout url passed by the
    portal in the JWT message).

    """
    form_class = forms.JWTDecryptForm

    def form_valid(self, form):
        """Redirect to the django logout page

        The JWT message's content is now the form's cleaned data. So we start
        out by extracting the contents. Then we extract the logout url on the
        portal.

        Args:
            form: A :class:`lizard_auth_server.forms.JWTDecryptForm`
                instance. It will have the JWT message contents in the
                ``cleaned_data`` attribute. ``logout_url`` is a mandatory key
                in the message.

        Raises:
            ValidationError: when the logout url is missing from the decoded
                JWT message.

        """
        # Check JWT message contents
        if not 'logout_url' in form.cleaned_data:
            raise ValidationError(
                "'logout_url' is missing from the JWT message")
        # Handle the logout.
        djangos_logout_url = reverse('django.contrib.auth.views.logout')
        logout_redirect_back_url = reverse('lizard_auth_server.api_v2.logout_redirect_back')
        params_for_logout_redirect_back_view = {
            'message': self.request.GET['message'],
            'key': self.request.GET['key'],
        }

        # after logout redirect user to the portal
        params = urlencode({
            'next': '%s?%s' % (logout_redirect_back_url,
                               urlencode(params_for_logout_redirect_back_view))
            })
        url = '%s?%s' % (djangos_logout_url, params)
        return HttpResponseRedirect(url)


class LogoutRedirectBackView(FormInvalidMixin, ProcessGetFormView):
    """Redirects the now-logged-out user to the logout page of the portal.

    See the documentation of
    :class:`lizard_auth_server.views_api_v2.LogoutView` for an explanation of
    the flow.

    """
    form_class = forms.JWTDecryptForm

    def form_valid(self, form):
        """Redirect back to the portal's own logout view.

        The JWT message's content is now the form's cleaned data. So we start
        out by extracting the contents. Then we extract the logout url on the
        portal.

        Args:
            form: A :class:`lizard_auth_server.forms.JWTDecryptForm`
                instance. It will have the same JWT message contents in the
                ``cleaned_data`` attribute as in
                :class:`lizard_auth_server.views_api_v2.LogoutView`.

        """
        # JWT message contents is the same as in LogoutView and has been
        # checked there. So we don't need to check for a missing logout_url
        # parameter.
        return HttpResponseRedirect(form.cleaned_data['logout_url'])
