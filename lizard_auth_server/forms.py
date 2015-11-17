# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django import forms
from django.conf import settings
from django.contrib import auth
from django.contrib.auth.models import User
from django.forms import ValidationError
from django.utils.translation import ugettext_lazy as _
from itsdangerous import BadSignature
from itsdangerous import URLSafeTimedSerializer
from lizard_auth_server.models import Organisation
from lizard_auth_server.models import Portal


MIN_LENGTH = 8


class DecryptForm(forms.Form):
    key = forms.CharField(max_length=1024)
    message = forms.CharField(max_length=8192)

    def clean(self):
        data = super(DecryptForm, self).clean()
        if 'key' not in data:
            raise ValidationError('No portal key')
        try:
            self.portal = Portal.objects.get(sso_key=data['key'])
        except Portal.DoesNotExist:
            raise ValidationError('Invalid portal key')
        try:
            new_data = URLSafeTimedSerializer(self.portal.sso_secret).loads(
                data['message'], max_age=300)
        except BadSignature:
            raise ValidationError('Bad signature')
        if data['key'] != new_data['key']:
            raise ValidationError('Public key does not match signed key')
        return new_data


def validate_password(cleaned_password):
    if settings.DEBUG:
        return

    # At least MIN_LENGTH long
    if len(cleaned_password) < MIN_LENGTH:
        raise ValidationError(
            _("The new password must be at least %d characters long.")
            % MIN_LENGTH)

    # Character requirements...
    digits = 0
    uppers = 0
    lowers = 0
    for char in cleaned_password:
        if char.isdigit():
            digits += 1
        if char.islower():
            uppers += 1
        if char.isupper():
            lowers += 1
    if digits < 2 or uppers < 1 or lowers < 1:
        raise ValidationError(
            _("The new password must contain at least two numeric digits, "
              "one uppercase and one lowercase character.")
        )


class AuthenticateUnsignedForm(forms.Form):
    key = forms.CharField(max_length=1024)
    username = forms.CharField(max_length=128)
    password = forms.CharField(max_length=128)

    def clean(self):
        data = super(AuthenticateUnsignedForm, self).clean()
        if 'key' not in data:
            raise ValidationError('No portal key')
        try:
            self.portal = Portal.objects.get(sso_key=data['key'])
        except Portal.DoesNotExist:
            raise ValidationError('Invalid portal key')
        return data


class PasswordChangeForm(auth.forms.PasswordChangeForm):
    """Used to verify whether the new password is secure."""

    def clean_new_password1(self):
        password1 = self.cleaned_data.get('new_password1')
        validate_password(password1)
        return password1


class SetPasswordForm(auth.forms.SetPasswordForm):
    """Used to verify whether the new password is secure."""

    def clean_new_password1(self):
        password1 = self.cleaned_data.get('new_password1')
        validate_password(password1)
        return password1


def organisation_choices():
    return [(organisation.name, organisation.name)
            for organisation in Organisation.objects.all()]


class InviteUserForm(forms.Form):
    """
    Form used by an administrator to invite a user.
    """

    def __init__(self, *args, **kwargs):
        super(InviteUserForm, self).__init__(*args, **kwargs)
        self.fields['organisation'].choices = organisation_choices()
        # TODO: in django 1.8 you can just set "choices =
        # organisation_choices" on the field.

    # Whitespace is allowed in `name` (it's only used in the invitation email).
    name = forms.CharField(
        max_length=64,
        label=_('Name'),
        required=True,
        help_text=_(
            'For the purpose of an invitation email (not the username)'
        ),
    )
    email = forms.EmailField(max_length=255, label=_('Email'), required=True)
    organisation = forms.ChoiceField(
        label=_('Organisation'),
        required=True,
        choices=[]
    )
    language = forms.ChoiceField(
        label=_('Language'),
        required=True,
        choices=[
            (lang_code, _(lang_name)) for lang_code, lang_name
            in settings.LANGUAGES
        ],
        widget=forms.RadioSelect(),
        initial='nl'
    )

    portals = forms.ModelMultipleChoiceField(
        label=_('Portals'),
        required=False,
        queryset=Portal.objects.all().order_by('name'),
        widget=forms.CheckboxSelectMultiple()
    )

    def clean_email(self):
        email = self.cleaned_data.get('email')
        users = User.objects.filter(email=email)
        if users.exists():
            raise ValidationError(_('{} is already taken.').format(email))
        return email


class ActivateUserForm1(forms.Form):
    """
    Form used by a user to activate his/her account.
    """
    # Do not allow whitespace in `username` (problematic with Django admin).
    username = forms.CharField(
        max_length=30,
        label=_('Username'),
        required=True
    )
    new_password1 = forms.CharField(
        label=_("New password"),
        widget=forms.PasswordInput
    )
    new_password2 = forms.CharField(
        label=_("New password confirmation"),
        widget=forms.PasswordInput
    )

    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
    }

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if " " in username:
            raise ValidationError(_('Whitespace not allowed.'))
        users = User.objects.filter(username=username)
        if users.exists():
            raise ValidationError(_('{} is already taken.').format(username))
        return username

    def clean_new_password1(self):
        password1 = self.cleaned_data.get('new_password1')
        validate_password(password1)
        return password1

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise ValidationError(self.error_messages['password_mismatch'])
        return password2


class EditProfileForm(forms.Form):
    """
    Form used by a user to activate his/her account.
    """
    email = forms.EmailField(max_length=255, label=_('Email'), required=True)
    first_name = forms.CharField(
        max_length=30,
        label=_('First name'),
        required=True
    )
    last_name = forms.CharField(
        max_length=30,
        label=_('Last name'),
        required=True
    )
    title = forms.CharField(max_length=255, label=_('Title'), required=False)
    street = forms.CharField(max_length=255, label=_('Street'), required=False)
    postal_code = forms.CharField(
        max_length=255,
        label=_('Postal code'),
        required=False
    )
    town = forms.CharField(max_length=255, label=_('Town'), required=False)
    phone_number = forms.CharField(
        max_length=255,
        label=_('Phone number'),
        required=False
    )
    mobile_phone_number = forms.CharField(
        max_length=255,
        label=_('Mobile phone number'),
        required=False
    )

    def __init__(self, user=None, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.user = user
        self.fields.keyOrder = [
            'email',
            'first_name',
            'last_name',
            'title',
            'street',
            'postal_code',
            'town',
            'phone_number',
            'mobile_phone_number',
        ]

    def clean_email(self):
        email = self.cleaned_data.get('email')
        users = User.objects.filter(email=email)
        if self.user:
            users = users.exclude(pk=self.user.pk)
        if users.exists():
            raise ValidationError(_('{} is already taken.').format(email))
        return email
