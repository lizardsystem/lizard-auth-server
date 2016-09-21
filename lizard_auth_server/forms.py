# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django import forms
from django.conf import settings
from django.contrib.auth import forms as authforms
from django.contrib.auth.models import User
from django.forms import ValidationError
from django.utils.translation import ugettext_lazy as _
from itsdangerous import BadSignature
from itsdangerous import URLSafeTimedSerializer
import jwt

from lizard_auth_server.models import BILLING_ROLE
from lizard_auth_server.models import Organisation
from lizard_auth_server.models import Portal
from lizard_auth_server.models import THREEDI_PORTAL
from lizard_auth_server.models import UserProfile

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


class JWTDecryptForm(forms.Form):
    """Form for decoding and validating JWT messages

    The form is different from regular django forms. There are two
    **incoming** form fields, but the message payload is used as the
    **outgoing** ``cleaned_data``.

    Note: there is *no* form validation on the actual message contents.

    The "incoming" form fields:

    key
        ID identifying the :term:`portal`. In lizard-auth-client this is the
        ``SSO_KEY`` setting.
    message
        The JWT message containing the payload and the JWT signature.

    The :meth:`.clean` method does the actual JWT decoding and validation.

    """
    key = forms.CharField(max_length=1024)
    message = forms.CharField(max_length=8192)

    def clean(self):
        """Verify the JWT signature and return the JWT payload

        The ``key`` field is used to look up the relevant :term:`portal`. That
        site's ``sso_secret`` is used to validate the signature on the JWT
        payload. This way we can be sure that the payload has been really send
        by the :term:`portal` we think send it and that the payload has not been
        tampered with.

        The payload MUST contain a value for ``key`` that matches the ``key``
        form field: this is needed to verify that the payload has not been
        tampered with.

        Returns:

            The JWT payload is returned **instead of** the original form
            data. So the JWT payload ends up in the form's ``cleaned_data``
            attribute instead of the original key+message fields!

        Raises:

            ValidationError: When the JWT is malformed or expired or when the
                signature does not match. A :term:`portal` should be found
                that matches ``key``. Likewise, ``key`` in the payload should
                match the ``key`` form field.

        """
        original_cleaned_data = super(JWTDecryptForm, self).clean()
        if 'key' not in original_cleaned_data:
            raise ValidationError('No SSO key')
        try:
            self.portal = Portal.objects.get(sso_key=original_cleaned_data['key'])
        except Portal.DoesNotExist:
            raise ValidationError('Invalid SSO key')
        try:
            new_cleaned_data = jwt.decode(original_cleaned_data['message'],
                                          self.portal.sso_secret,
                                          algorithms=['HS256'])
        except jwt.exceptions.DecodeError:
            raise ValidationError("Failed to decode JWT.")
        except jwt.exceptions.ExpiredSignatureError:
            raise ValidationError("JWT has expired.")

        # This is useful for verifying if the key of the GET parameter (which
        # could be tampered with) is same as the key in the payload.
        if original_cleaned_data['key'] != new_cleaned_data['key']:
            raise ValidationError('Public SSO key does not match signed key')
        return new_cleaned_data


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


class PasswordChangeForm(authforms.PasswordChangeForm):
    """Used to verify whether the new password is secure."""

    def clean_new_password1(self):
        password1 = self.cleaned_data.get('new_password1')
        validate_password(password1)
        return password1


class SetPasswordForm(authforms.SetPasswordForm):
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


class UserProfileForm(forms.ModelForm):

    class Meta:
        model = UserProfile
        # TODO: 1.8 change
        fields = '__all__'
        # ^^^ Or a list of the fields that you want to include in your form.

    def clean(self):
        """Check 3Di-specific requirements"""
        cleaned_data = super(UserProfileForm, self).clean()
        portals = cleaned_data.get('portals')
        if not [portal for portal in portals if portal.name == THREEDI_PORTAL]:
            # We don't need to check
            return cleaned_data
        # Note: roles below is really organisation_roles...
        organisation_roles = self.cleaned_data.get('roles')
        num_threedi_billing_roles = len([
            organisation_role for organisation_role in organisation_roles
            if organisation_role.role.code == BILLING_ROLE and
            organisation_role.role.portal.name == THREEDI_PORTAL])
        if num_threedi_billing_roles == 0:
            self._errors['roles'] = self.error_class([
                _('required 3Di billing role is missing')])
        if num_threedi_billing_roles >= 2:
            self._errors['roles'] = self.error_class([
                _('Only one 3Di billing role is allowed ({} found)').format(
                    num_threedi_billing_roles)])
        print(self._errors)
        return cleaned_data
