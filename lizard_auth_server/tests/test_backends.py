"""Mostly copied from django-warrant's tests.py."""

from django.conf import settings
from django.test import TestCase, override_settings
from lizard_auth_server import backends
from unittest import mock


def get_user(cls, *args, **kwargs):
    user = {
        "user_status": kwargs.pop("user_status", "CONFIRMED"),
        "username": kwargs.pop("access_token", "testuser"),
        "email": kwargs.pop("email", "test@email.com"),
        "given_name": kwargs.pop("given_name", "FirstName"),
        "family_name": kwargs.pop("family_name", "LastName"),
        "UserAttributes": [
            {"Name": "sub", "Value": "c7d890f6-eb38-498d-8f85-7a6c4af33d7a"},
            {"Name": "email_verified", "Value": "true"},
            {"Name": "gender", "Value": "male"},
            {"Name": "name", "Value": "FirstName LastName"},
            {"Name": "preferred_username", "Value": "testuser"},
            {"Name": "given_name", "Value": "FirstName"},
            {"Name": "family_name", "Value": "LastName"},
            {"Name": "email", "Value": "test@email.com"},
            {"Name": "custom:api_key", "Value": "abcdefg"},
            {"Name": "custom:api_key_id", "Value": "ab-1234"},
        ],
    }
    user_metadata = {
        "username": user.get("Username"),
        "id_token": cls.id_token,
        "access_token": cls.access_token,
        "refresh_token": cls.refresh_token,
        "api_key": user.get("custom:api_key", None),
        "api_key_id": user.get("custom:api_key_id", None),
    }

    return cls.get_user_obj(
        username=cls.username,
        attribute_list=user.get("UserAttributes"),
        metadata=user_metadata,
    )


@override_settings(
    AUTHENTICATION_BACKENDS=[
        "lizard_auth_server.backends.CognitoBackend",
        "django.contrib.auth.backends.ModelBackend",
    ],
)
@mock.patch("lizard_auth_server.backends.CognitoUser.__init__")
class TestCognitoUser(TestCase):
    def test_smoke(self, patched_init):
        """Quick test

        The code has been mostly been copied from django-warrant and has been
        tested there, so I'm not going to re-build the entire test
        infrastructure here, especially as calls to amazon are being made.

        """
        patched_init.return_value = None
        # Example user is mostly copied from django-warrant's tests.
        example_user = {
            "user_status": "CONFIRMED",
            "username": "testuser",
            "email": "test@email.com",
            "given_name": "FirstName",
            "family_name": "LastName",
            "UserAttributes": [
                {"Name": "sub", "Value": "c7d890f6-eb38-498d-8f85-7a6c4af33d7a"},
                {"Name": "email_verified", "Value": "true"},
                {"Name": "gender", "Value": "male"},
                {"Name": "name", "Value": "FirstName LastName"},
                {"Name": "preferred_username", "Value": "testuser"},
                {"Name": "given_name", "Value": "FirstName"},
                {"Name": "family_name", "Value": "LastName"},
                {"Name": "email", "Value": "test@email.com"},
                {"Name": "custom:api_key", "Value": "abcdefg"},
                {"Name": "custom:api_key_id", "Value": "ab-1234"},
            ],
        }
        attribute_list = example_user["UserAttributes"]
        cognito_user = backends.CognitoUser()
        django_user1 = cognito_user.get_user_obj(
            username="test", attribute_list=attribute_list
        )
        self.assertEqual(django_user1.email, "test@email.com")
        self.assertTrue(django_user1.user_profile.migrated_at)
        # Doing it a second time reuses the exisiting user.
        django_user2 = cognito_user.get_user_obj(
            username="test", attribute_list=attribute_list
        )
        self.assertEqual(django_user2.id, django_user1.id)

    def test_admin_set_password(self, patched_init):
        patched_init.return_value = None
        cognito_user = backends.CognitoUser()

        cognito_user.client = mock.Mock()  # the boto3 client
        cognito_user.username = "testuser"
        cognito_user.user_pool_id = "foo"

        cognito_user.admin_set_user_password("bar")

        # AdminSetUserPassword should be called as documented
        args, kwargs = cognito_user.client.admin_set_user_password.call_args
        expected = {
            "UserPoolId": "foo",
            "Username": "testuser",
            "Password": "bar",
            "Permanent": True,
        }
        self.assertDictEqual(expected, kwargs)

    def test_admin_user_exists(self, patched_init):
        patched_init.return_value = None
        cognito_user = backends.CognitoUser()

        cognito_user.client = mock.Mock()  # the boto3 client
        cognito_user.username = "testuser"
        cognito_user.user_pool_id = "foo"

        cognito_user.admin_user_exists()

        # AdminGetUser should be called as documented
        args, kwargs = cognito_user.client.admin_get_user.call_args
        expected = {
            "UserPoolId": "foo",
            "Username": "testuser",
        }
        self.assertDictEqual(expected, kwargs)
