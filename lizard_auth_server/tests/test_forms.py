from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.test import override_settings
from django.test import TestCase
from lizard_auth_server.forms import JWTDecryptForm
from lizard_auth_server.forms import SetPasswordMixin
from unittest import mock


class TestForm(TestCase):
    def test_smoke(self):
        jwtform = JWTDecryptForm()
        self.assertTrue(jwtform is not None)


@override_settings(AWS_ACCESS_KEY_ID="something")
class TestSetPasswordMixin(TestCase):
    def setUp(self):
        # self.user = User.objects.create(username="testuser")
        # self.user.set_password("pwd")

        self.form = SetPasswordMixin()
        self.form.cleaned_data = {}
        self.form.error_messages = {"password_incorrect": "bla"}
        self.form.user = User(username="testuser")

    @mock.patch("lizard_auth_server.forms.CognitoUser")
    def test_save(self, CognitoUser_m):
        # Mock save of password through CognitoUser().admin_set_user_password
        cognito_user = CognitoUser_m.from_username.return_value
        admin_set_user_password = cognito_user.admin_set_user_password

        # Now save a new password
        self.form.cleaned_data["new_password1"] = "foo"
        self.form.save()

        # Check the construction of CognitoUser
        self.assertEqual(("testuser",), CognitoUser_m.from_username.call_args[0])
        # Check the call to admin_set_user_password
        self.assertEqual(
            ("foo",),
            admin_set_user_password.call_args[0],
        )

    @mock.patch("lizard_auth_server.forms.CognitoBackend")
    def test_clean_old_password_correct(self, CognitoBackend_m):
        # Simulate successful authentication with old_password
        authenticate = CognitoBackend_m.return_value.authenticate
        authenticate.return_value = User()

        # Now clean a correct old_password
        self.form.cleaned_data["old_password"] = "correct"
        self.assertEqual("correct", self.form.clean_old_password())

        # Check the authenticate call
        self.assertDictEqual(
            {"username": "testuser", "password": "correct"},
            authenticate.call_args[1],
        )

    @mock.patch("lizard_auth_server.forms.CognitoBackend")
    def test_clean_old_password_wrong(self, CognitoBackend_m):
        # Simulate failed authentication with old_password
        authenticate = CognitoBackend_m.return_value.authenticate
        authenticate.return_value = None

        # Now clean a wrong old_password
        self.form.cleaned_data["old_password"] = "wrong"
        self.assertRaises(ValidationError, self.form.clean_old_password)

        # Check the authenticate call
        self.assertDictEqual(
            {"username": "testuser", "password": "wrong"},
            authenticate.call_args[1],
        )
