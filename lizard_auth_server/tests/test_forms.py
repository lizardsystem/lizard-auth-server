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

    def test_jwt_field_validates(self):
        """JWTField validates with the correct secret key."""
        jwtfield = JWTField()
        jwtfield.secret_key = self.secret_key
        jwtfield.clean(self.message)

    def test_jwt_field_wrong_key(self):
        """JWTField doesn't validate with the wrong secret key."""
        jwtfield = JWTField()
        jwtfield.clean(self.message)
        with self.assertRaises(ValidationError):
            jwtfield.verify_signature('pietje')

    def test_jwt_field_nonrequired_keys(self):
        """JWTField doesn't validate with unknown required_keys."""
        jwtfield = JWTField(required_keys=('unknown_key',))
        with self.assertRaises(ValidationError):
            jwtfield.clean(self.message)

    def test_jwt_field_required_keys(self):
        """JWTField validates with correct required_keys."""
        jwtfield = JWTField(required_keys=('foo',))
        jwtfield.clean(self.message)
