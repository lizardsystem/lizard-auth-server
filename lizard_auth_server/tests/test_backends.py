"""Mostly copied from django-warrant's tests.py."""

from botocore.exceptions import ClientError
from django.conf import settings
from django.contrib.auth import authenticate as django_authenticate
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import override_settings
from django.test import TestCase
from importlib import import_module
from mock import patch
from warrant import Cognito


def set_tokens(cls, *args, **kwargs):
    cls.access_token = "accesstoken"
    cls.id_token = "idtoken"
    cls.refresh_token = "refreshtoken"


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


def create_request():
    request = HttpRequest()
    engine = import_module(settings.SESSION_ENGINE)
    session = engine.SessionStore()
    session.save()
    request.session = session

    return request


def authenticate(username, password):
    request = create_request()
    return django_authenticate(request=request, username=username, password=password)


def login(client, username, password):
    request = create_request()
    return client.login(request=request, username=username, password=password)


class AuthTests(TestCase):
    @patch.object(Cognito, "authenticate")
    @patch.object(Cognito, "get_user")
    def test_user_authentication(self, mock_get_user, mock_authenticate):
        Cognito.authenticate = set_tokens
        Cognito.get_user = get_user
        user = authenticate(username="testuser", password="password")

        self.assertIsNotNone(user)

    @patch.object(Cognito, "authenticate")
    def test_user_authentication_wrong_password(self, mock_authenticate):
        Cognito.authenticate.side_effect = ClientError(
            {
                "Error": {
                    "Message": "Incorrect username or password.",
                    "Code": "NotAuthorizedException",
                }
            },
            "AdminInitiateAuth",
        )
        user = authenticate(username="username", password="wrongpassword")

        self.assertIsNone(user)

    @patch.object(Cognito, "authenticate")
    def test_user_authentication_wrong_username(self, mock_authenticate):
        Cognito.authenticate.side_effect = ClientError(
            {
                "Error": {
                    "Message": "Incorrect username or password.",
                    "Code": "NotAuthorizedException",
                }
            },
            "AdminInitiateAuth",
        )
        user = authenticate(username="wrongusername", password="password")

        self.assertIsNone(user)

    @patch.object(Cognito, "authenticate")
    @patch.object(Cognito, "get_user")
    def test_client_login(self, mock_get_user, mock_authenticate):
        Cognito.authenticate = set_tokens
        Cognito.get_user = get_user
        user = login(self.client, username="testuser", password="password")
        self.assertTrue(user)

    @patch.object(Cognito, "authenticate")
    def test_boto_error_raised(self, mock_authenticate):
        """
        Check that any error other than NotAuthorizedException is
        raised as an exception
        """
        Cognito.authenticate.side_effect = ClientError(
            {"Error": {"Message": "Generic Error Message.", "Code": "SomeError"}},
            "AdminInitiateAuth",
        )
        with self.assertRaises(ClientError) as error:
            user = authenticate(username="testuser", password="password")
        self.assertEqual(error.exception.response["Error"]["Code"], "SomeError")

    @patch.object(Cognito, "authenticate")
    @patch.object(Cognito, "get_user")
    def test_new_user_created(self, mock_get_user, mock_authenticate):
        Cognito.authenticate = set_tokens
        Cognito.get_user = get_user

        User = get_user_model()
        self.assertEqual(User.objects.count(), 0)
        user = authenticate(username="testuser", password="password")

        self.assertEqual(User.objects.count(), 1)
        self.assertEqual(user.username, "testuser")

    @patch.object(Cognito, "authenticate")
    @patch.object(Cognito, "get_user")
    def test_existing_user_updated(self, mock_get_user, mock_authenticate):
        Cognito.authenticate = set_tokens
        Cognito.get_user = get_user

        User = get_user_model()
        existing_user = User.objects.create(username="testuser", email="None")
        user = authenticate(username="testuser", password="password")
        self.assertEqual(user.id, existing_user.id)
        self.assertNotEqual(user.email, existing_user.email)
        self.assertEqual(User.objects.count(), 1)

        updated_user = User.objects.get(username="testuser")
        self.assertEqual(updated_user.email, user.email)
        self.assertEqual(updated_user.id, user.id)

    @override_settings(COGNITO_CREATE_UNKNOWN_USERS=False)
    @patch.object(Cognito, "authenticate")
    @patch.object(Cognito, "get_user")
    def test_existing_user_updated_disabled_create_unknown_user(
        self, mock_get_user, mock_authenticate
    ):
        Cognito.authenticate = set_tokens
        Cognito.get_user = get_user

        User = get_user_model()
        existing_user = User.objects.create(username="testuser", email="None")

        user = authenticate(username="testuser", password="password")
        self.assertEqual(user.id, existing_user.id)
        self.assertNotEqual(user.email, existing_user)
        self.assertEqual(User.objects.count(), 1)

        updated_user = User.objects.get(username="testuser")
        self.assertEqual(updated_user.email, user.email)
        self.assertEqual(updated_user.id, user.id)

    @override_settings(COGNITO_CREATE_UNKNOWN_USERS=False)
    @patch.object(Cognito, "authenticate")
    @patch.object(Cognito, "get_user")
    def test_user_not_found_disabled_create_unknown_user(
        self, mock_get_user, mock_authenticate
    ):
        Cognito.authenticate = set_tokens
        Cognito.get_user = get_user

        user = authenticate(username="testuser", password="password")

        self.assertIsNone(user)
