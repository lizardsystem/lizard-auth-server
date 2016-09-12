from django.core.urlresolvers import reverse
from django.test import Client
from django.test import TestCase
from django.test.client import RequestFactory
from lizard_auth_server import models
from lizard_auth_server import views_api_v2
from lizard_auth_server.tests import factories


class TestVerifyCredentialsView(TestCase):
    def setUp(self):
        self.view = views_api_v2.VerifyCredentialsView.as_view()
        self.request_factory = RequestFactory()
        self.some_request = self.request_factory.get('/some/url/')

    def test_smoke(self):
        client = Client()
        result = client.get(reverse('lizard_auth_server.api_v2.authenticate'))
        self.assertEquals(400, result.status_code)
