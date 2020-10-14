from django.test import TestCase
from lizard_auth_server.forms import JWTDecryptForm


class TestForm(TestCase):
    def test_smoke(self):
        jwtform = JWTDecryptForm()
        self.assertTrue(jwtform is not None)
