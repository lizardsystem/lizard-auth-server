# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from datetime import datetime
import jwt
import logging

from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
from django.core.validators import URLValidator
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponseRedirect
from django.shortcuts import redirect
from django.template.context import RequestContext
from django.template.response import TemplateResponse
from django.utils.decorators import method_decorator
from django.utils.functional import cached_property
from django.utils.translation import ugettext as _
from django.views.generic import View
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView

# urllib is the hardest module to use from Python 2/3 compatible code. Six
# provides a version for wrapping over differences between Python 2 and 3.
from six.moves.urllib import parse

from lizard_auth_server import forms
from lizard_auth_server.conf import settings
from lizard_auth_server.models import Invitation
from lizard_auth_server.models import Portal

JWT_ALGORITHM = settings.LIZARD_AUTH_SERVER_JWT_ALGORITHM
JWT_EXPIRATION_DELTA = settings.LIZARD_AUTH_SERVER_JWT_EXPIRATION_DELTA

logger = logging.getLogger(__name__)


class ViewContextMixin(object):
    """
    Adds the view object to the template context.

    Ensure this is first in the inheritance list!
    """

    # TODO: zap this after some tests have been added. Django 1.4 or so
    # already includes this!

    def get_context_data(self, **kwargs):
        return {
            'params': kwargs,
            'view': self
        }


class StaffOnlyMixin(object):
    """
    Ensures access by staff members (user.is_staff is True) only to all
    HTTP methods.

    Ensure this is first in the inheritance list!
    """
    @method_decorator(staff_member_required)
    def dispatch(self, request, *args, **kwargs):
        return super(StaffOnlyMixin, self).dispatch(request, *args, **kwargs)


class ErrorMessageResponse(TemplateResponse):
    """
    Display a slightly more user-friendly error message.
    """
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

##################################################
# Invitation / registration / activation / profile
##################################################


class ProfileView(ViewContextMixin, TemplateView):
    """
    Straightforward view which displays a user's profile.
    """
    template_name = 'lizard_auth_server/profile.html'

    @cached_property
    def profile(self):
        return self.request.user.get_profile()

    @property
    def portals(self):
        if self.request.user.is_staff:
            return Portal.objects.all()
        else:
            return self.profile.portals.all()

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(ProfileView, self).dispatch(request, *args, **kwargs)


class AccessToPortalView(ViewContextMixin, TemplateView):
    template_name = 'lizard_auth_server/access-to-portal.html'

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(AccessToPortalView, self).dispatch(
            request, *args, **kwargs)

    @cached_property
    def portal(self):
        portal_pk = self.kwargs['portal_pk']
        return Portal.objects.get(id=portal_pk)

    @cached_property
    def title(self):
        return _('Access to portal {} for {}').format(self.portal.name,
                                                      self.profile)

    @cached_property
    def profile(self):
        if self.request.user.is_staff:
            user_id = self.kwargs.get('user_pk')
            if user_id:
                user = User.objects.get(id=user_id)
                return user.get_profile()
        return self.request.user.get_profile()

    @cached_property
    def organisation_roles_explanation(self):
        if not self.request.user.is_staff:
            return
        return self.profile.all_organisation_roles(
            self.portal,
            return_explanation=True)

    @cached_property
    def user_profiles_for_portal(self):
        if not self.request.user.is_staff:
            return
        return self.portal.user_profiles.select_related('user')

    @cached_property
    def my_organisation_roles_for_this_portal(self):
        return self.profile.all_organisation_roles(self.portal)


class EditProfileView(FormView):
    """
    Straightforward view which displays a form to have a user
    edit his / her own profile.
    """
    template_name = 'lizard_auth_server/edit_profile.html'
    form_class = forms.EditProfileForm
    _profile = None

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(EditProfileView, self).dispatch(request, *args, **kwargs)

    @property
    def profile(self):
        if not self._profile:
            self._profile = self.request.user.get_profile()
        return self._profile

    def get_initial(self):
        return {
            'email': self.profile.email,
            'first_name': self.profile.first_name,
            'last_name': self.profile.last_name,
            'title': self.profile.title,
            'street': self.profile.street,
            'postal_code': self.profile.postal_code,
            'town': self.profile.town,
            'phone_number': self.profile.phone_number,
            'mobile_phone_number': self.profile.mobile_phone_number
        }

    def get_form(self, form_class):
        return form_class(user=self.request.user, **self.get_form_kwargs())

    def form_valid(self, form):
        data = form.cleaned_data

        # let the model handle the rest
        self.profile.update_all(data)

        return HttpResponseRedirect(reverse('profile'))


class InviteUserView(StaffOnlyMixin, FormView):
    template_name = 'lizard_auth_server/invite_user.html'
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

        return HttpResponseRedirect(
            reverse(
                'lizard_auth_server.invite_user_complete',
                kwargs={'invitation_pk': inv.pk}))


class InviteUserCompleteView(StaffOnlyMixin, ViewContextMixin, TemplateView):
    template_name = 'lizard_auth_server/invite_user_complete.html'

    def get(self, request, invitation_pk, *args, **kwargs):
        self.invitation_pk = int(invitation_pk)
        return super(
            InviteUserCompleteView, self).get(request, *args, **kwargs)

    @cached_property
    def invitiation(self):
        return Invitation.objects.get(pk=self.invitation_pk)


class InvitationMixin(object):
    invitation = None
    activation_key = None
    error_on_already_used = True

    def dispatch(self, request, activation_key, *args, **kwargs):
        self.activation_key = activation_key
        try:
            self.invitation = Invitation.objects.get(
                activation_key=self.activation_key)
        except Invitation.DoesNotExist:
            return self.invalid_activation_key(request)

        # show a semi-nice error page if the invitation was already used
        if self.error_on_already_used and self.invitation.is_activated:
            return self.invalid_activation_key(request)

        return super(InvitationMixin, self).dispatch(request, *args, **kwargs)

    def invalid_activation_key(self, request):
        logger.warn(
            'invalid activation key used by %s',
            request.META['REMOTE_ADDR'])
        return ErrorMessageResponse(
            request,
            _('Invalid activation key. Perhaps this account '
              'was already activated?'), 404)


class ActivateUserView1(InvitationMixin, FormView):
    template_name = 'lizard_auth_server/activate_user.html'
    form_class = forms.ActivateUserForm1

    def form_valid(self, form):
        data = form.cleaned_data

        # let the model handle the rest
        self.invitation.create_user(data)

        return HttpResponseRedirect(
            reverse(
                'lizard_auth_server.activate_step_2',
                kwargs={'activation_key': self.activation_key}))


class ActivateUserView2(InvitationMixin, FormView):
    template_name = 'lizard_auth_server/activate_user_step_2.html'
    form_class = forms.EditProfileForm

    def get_initial(self):
        return {
            'email': self.invitation.email,
        }

    def form_valid(self, form):
        data = form.cleaned_data

        # let the model handle the rest
        self.invitation.activate(data)

        return HttpResponseRedirect(
            reverse(
                'lizard_auth_server.activation_complete',
                kwargs={'activation_key': self.activation_key}))


class ActivationCompleteView(InvitationMixin, TemplateView):
    template_name = 'lizard_auth_server/activation_complete.html'
    error_on_already_used = False  # see InvitationMixin
    _profile = None

    @property
    def profile(self):
        if not self._profile:
            self._profile = self.invitation.user.get_profile()
        return self._profile


class JWTView(View):
    """A view for authenticating to an SSO-managed portal with a JSON Web Token.

    Anonymous users will first be redirected to a login form. Authenticated
    users will receive a (new) token right away.

    The query string may have a `next` parameter used for redirection. If
    present, it must be a fully qualified URL starting with http(s). The
    token will be attached to the query string as an extra parameter:
    <next>?foo=bar&access_token=xxxxx.yyyyy.zzzzz&...

    If a `next` parameter is absent, a JSON response is returned:

    {"access_token": "xxxxx.yyyyy.zzzzz"}

    """

    @staticmethod
    def is_url(url):
        """Validate a URL.

        The current validator accepts only absolute URLs, which makes
        sense as the token is to be generated for another portal.

        Args:
            url (str): an absolute, i.e. fully qualified, URL.

        Returns:
            bool: True if valid, False otherwise.

        """
        val = URLValidator()
        try:
            val(url)
            return True
        except ValidationError:
            return False

    @staticmethod
    def is_portal(sso_key):
        """Validate a portal.

        Args:
            sso_key (str): a public key identifying the portal.

        Returns:
            bool: True if the portal exists, False otherwise.

        """
        return Portal.objects.filter(sso_key=sso_key).exists()

    @staticmethod
    def get_token(user, portal, exp=None):
        """Return a JSON Web Token.

        Args:
            user (django.contrib.auth.models.User): an active, authenticated
                user that has access to the portal.
            portal (lizard_auth_server.models.Portal): a Portal instance.
            exp (int/datetime): expiration time - in UTC - on or after
                the token must not be accepted for processing.

        Returns:
            str: A JSON Web Token.

        """
        assert(user.is_active and user.is_authenticated())
        assert(user.user_profile.has_access(portal))
        if exp is None:
            exp = datetime.utcnow() + JWT_EXPIRATION_DELTA
        payload = {'exp': exp, 'username': user.username}
        secret = portal.sso_secret
        token = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)
        return token

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(JWTView, self).dispatch(*args, **kwargs)

    def get(self, request, *args, **kwargs):
        """Return a token.

        If the request has a `next` query string parameter, the response will
        be a redirect (302) and the token is added to the `next` URL. If a
        `next` parameter is absent, a JSON response is returned.

        An HTTP 400 Bad Request is returned in case of trouble.

        """
        self.redirect_to = request.GET.get('next', '')
        sso_key = request.GET.get('portal', '')

        if self.redirect_to and not JWTView.is_url(self.redirect_to):
            reason = _('Invalid `next` query string parameter.')
            return HttpResponseBadRequest(reason, content_type='text/plain')

        if not sso_key:
            reason = _('Missing `portal` query string parameter.')
            return HttpResponseBadRequest(reason, content_type='text/plain')

        if not JWTView.is_portal(sso_key):
            reason = _('Invalid `portal` query string parameter.')
            return HttpResponseBadRequest(reason, content_type='text/plain')

        portal = Portal.objects.get(sso_key=sso_key)

        if not request.user.user_profile.has_access(portal):
            reason = _('You do not have access to this portal.')
            return HttpResponseBadRequest(reason, content_type='text/plain')

        self.token = JWTView.get_token(request.user, portal)

        if self.redirect_to:
            return redirect(self.success_url)
        else:
            return HttpResponse(self.token, content_type='text/plain')

    @property
    def success_url(self):
        """Return the `next` URL with a token as query string parameter."""
        # URL to parts.
        scheme, netloc, path, params, query, fragment = parse.urlparse(
            self.redirect_to)
        # Add (extra) query string parameter.
        data = parse.parse_qs(query)
        data['access_token'] = self.token
        query = parse.urlencode(data, True)
        # Parts to URL.
        url = parse.urlunparse((
            scheme, netloc, path, params, query, fragment))
        return str(url)
