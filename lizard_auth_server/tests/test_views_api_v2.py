from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.test import Client
from django.test import TestCase
from django.test.client import RequestFactory
from lizard_auth_server import views_api_v2
from lizard_auth_server.tests import factories
from mock import Mock


class TestVerifyCredentialsView(TestCase):
    def setUp(self):
        self.view = views_api_v2.VerifyCredentialsView()
        self.request_factory = RequestFactory()
        self.some_request = self.request_factory.get('/some/url/')
        self.organisation = factories.OrganisationF()
        self.username = 'reinout'
        self.password = 'annie'
        self.user = factories.UserF(username=self.username,
                                    password=self.password)
        self.portal = factories.PortalF()

    def test_disallowed_get(self):
        client = Client()
        result = client.get(
            reverse('lizard_auth_server.api_v2.check_credentials'))
        self.assertEquals(405, result.status_code)

    def test_smoke_post(self):
        client = Client()
        result = client.post(
            reverse('lizard_auth_server.api_v2.check_credentials'))
        self.assertEquals(400, result.status_code)

    def test_valid_login(self):
        # We don't need to check portal access anymore.
        form = Mock()
        form.cleaned_data = {'username': self.username,
                             'password': self.password}
        form.portal = self.portal  # This is extracted by the form.

        result = self.view.form_valid(form)
        self.assertEquals(200, result.status_code)

    def test_invalid_login(self):
        form = Mock()
        form.cleaned_data = {'username': 'pietje',
                             'password': 'ikkanniettypen'}
        self.assertRaises(PermissionDenied, self.view.form_valid, form)
