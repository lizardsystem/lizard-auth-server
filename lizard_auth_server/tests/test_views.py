from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.test import Client
from django.test import TestCase
from lizard_auth_server.tests import factories


class ProfileViewTestCase(TestCase):

    def test_smoke_as_regular_user(self):
        self.user = User.objects.create_user('someone', 'a@a.nl', 'pass')
        self.user_profile = factories.UserProfileF(user=self.user)
        self.client = Client()
        self.client.login(username='someone', password='pass')
        result = self.client.get(reverse('index'))
        self.assertEquals(result.status_code, 200)

    def test_smoke_as_admin(self):
        self.user = User.objects.create_superuser('admin', 'a@a.nl', 'pass')
        self.user_profile = factories.UserProfileF(user=self.user)
        self.client = Client()
        self.client.login(username='admin', password='pass')
        result = self.client.get(reverse('index'))
        self.assertEquals(result.status_code, 200)
