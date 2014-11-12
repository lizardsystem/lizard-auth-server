# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging

from django.core.urlresolvers import reverse
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.views.generic.edit import FormView
from django.utils.translation import ugettext as _
from django.http import (
    HttpResponseRedirect
)
from django.utils.decorators import method_decorator
from django.views.generic.base import TemplateView
from django.template.context import RequestContext
from django.template.response import TemplateResponse

from lizard_auth_server import forms
from lizard_auth_server.models import Portal, Invitation

logger = logging.getLogger(__name__)


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

##################################################
# Invitation / registration / activation / profile
##################################################


class ProfileView(ViewContextMixin, TemplateView):
    '''
    Straightforward view which displays a user's profile.
    '''
    template_name = 'lizard_auth_server/profile.html'
    _profile = None

    @property
    def profile(self):
        if not self._profile:
            self._profile = self.request.user.get_profile()
        return self._profile

    @property
    def all_portals(self):
        return Portal.objects.all()

    @method_decorator(login_required)
    def dispatch(self, request, *args, **kwargs):
        return super(ProfileView, self).dispatch(request, *args, **kwargs)


class EditProfileView(FormView):
    '''
    Straightforward view which displays a form to have a user
    edit his / her own profile.
    '''
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
    _invitiation = None

    def get(self, request, invitation_pk, *args, **kwargs):
        self.invitation_pk = int(invitation_pk)
        return super(
            InviteUserCompleteView, self).get(request, *args, **kwargs)

    @property
    def invitiation(self):
        if not self._invitiation:
            self._invitiation = Invitation.objects.get(pk=self.invitation_pk)
        return self._invitiation


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
            'invalid activation key used by {}'
            .format(request.META['REMOTE_ADDR']))
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
