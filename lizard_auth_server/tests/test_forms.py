from django.forms import ValidationError
from django.test import TestCase
import jwt

from lizard_auth_server.forms import (
    JWTField,
    JWTDecryptForm,
)

ALGORITHM = 'HS256'


class TestFormField(TestCase):

    def setUp(self):
        self.sso_key = "some sso key"
        self.secret_key = "a secret"
        self.payload = {
            "foo": "bar"
            }
        self.message = jwt.encode(self.payload, self.secret_key,
                                  algorithm=ALGORITHM)

    def test_smoke(self):
        jwtfield = JWTField()
        self.assertTrue(jwtfield is not None)

    def test_jwt_field_no_secret_key(self):
        """Test that the JWTField gives an exception when the secret key
        isn't set"""
        jwtfield = JWTField()
        with self.assertRaises(ValidationError):
            jwtfield.clean(self.message)

    def test_jwt_field_validates(self):
        """JWTField validates with the correct secret key."""
        jwtfield = JWTField()
        jwtfield.secret_key = self.secret_key
        jwtfield.clean(self.message)

    def test_jwt_field_wrong_key(self):
        """JWTField doesn't validate with the wrong secret key."""
        jwtfield = JWTField()
        jwtfield.secret_key = "not the right key"
        with self.assertRaises(ValidationError):
            jwtfield.clean(self.message)

    def test_jwt_field_unallowed_keys(self):
        """JWTField doesn't validate with unknown allowed_keys."""
        jwtfield = JWTField(allowed_keys=('unknown_key',))
        jwtfield.secret_key = self.secret_key
        with self.assertRaises(ValidationError):
            jwtfield.clean(self.message)

    def test_jwt_field_allowed_keys(self):
        """JWTField validates with correct allowed_keys."""
        jwtfield = JWTField(allowed_keys=('foo',))
        jwtfield.secret_key = self.secret_key
        jwtfield.clean(self.message)
