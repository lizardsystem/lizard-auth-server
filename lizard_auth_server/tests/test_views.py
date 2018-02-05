# -*- coding: utf-8 -*-

from datetime import datetime

import jwt
from faker import Faker
from jwt.exceptions import ExpiredSignatureError
from nose.tools import raises

from django.contrib.auth.models import AnonymousUser
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.test import Client
from django.test import TestCase
from django.test.client import RequestFactory
from lizard_auth_server.conf import settings
from lizard_auth_server.models import GenKey
from lizard_auth_server.tests import factories
from lizard_auth_server.views import JWTView

JWT_EXPIRATION_DELTA = settings.LIZARD_AUTH_SERVER_JWT_EXPIRATION_DELTA

fake = Faker()


class ProfileViewTestCase(TestCase):

    def test_smoke_as_regular_user(self):
        User.objects.create_user('someone', 'a@a.nl', 'pass')
        client = Client()
        client.login(username='someone', password='pass')
        result = client.get(reverse('index'))
        self.assertEquals(result.status_code, 200)

    def test_smoke_as_admin(self):
        User.objects.create_superuser('admin', 'a@a.nl', 'pass')
        client = Client()
        client.login(username='admin', password='pass')
        result = client.get(reverse('index'))
        self.assertEquals(result.status_code, 200)


class ManagePermissionViewTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.portal = factories.PortalF()
        self.user = factories.UserF()
        #zorg dat er een UserConsent object is in de db (in factory of hier?).

        #Get the list of all users before the tests.
        # self.users_before = list(User.objects.values_list('id', flat=True))

    def test_remove_one_and_correct_user_from_UserConsent(self):
        '''
        1) verwijder 1 object uit de UserConsent (via delete knop)
        UserConsent.user(Client_test).delete()
            --> maar zo kan de test al werken zonder goede code.

        2) Get the list of all users after the tests.
        users_after = list(User.objects.values_list('id', flat=True))

        3) Calculate the set difference is 1.
        users_removed= users_after - self.users_before
        self.assertEqual(1, user_removed)

        4) does this need a new test: verifying if correct user is removed
        search on the user that is removed in previous test
        user_to_remove not in users_removed
        expect attribute error.
        '''

    def test_remove_two_and_correct_users_from_UserConsent(self):
        '''
        1) verwijder 2 object uit de UserConsent (via delete knop)

        2) Get the list of all users after the tests.
        users_after = list(User.objects.values_list('id', flat=True))

        3) Calculate the set difference is 2
        users_removed= users_after - self.users_before
        self.assertEqual(2, user_removed)

        4) search on the user that is removed in previous test
        user_to_remove not in users_removed
        expect attribute error.
        '''


class JWTViewTestCase(TestCase):

    def setUp(self):
        self.factory = RequestFactory()
        self.portal = factories.PortalF()
        self.user = factories.UserF()

    def test_absolute_url(self):
        self.assertTrue(JWTView.is_url(fake.url()))

    def test_invalid_portal(self):
        random_sso_key = GenKey('Portal', 'sso_key')
        self.assertFalse(JWTView.is_portal(sso_key=random_sso_key))

    def test_valid_portal(self):
        self.assertTrue(JWTView.is_portal(self.portal.sso_key))

    @raises(AssertionError)
    def test_token_for_inactive_user(self):
        user = factories.UserF(is_active=False)
        user.user_profile.portals.add(self.portal)
        JWTView.get_token(user, self.portal)

    @raises(AssertionError)
    def test_token_for_anonymous_user(self):
        user = AnonymousUser()
        JWTView.get_token(user, self.portal)

    @raises(AssertionError)
    def test_token_for_user_without_access(self):
        JWTView.get_token(self.user, self.portal)

    def test_token_with_exp_as_int(self):
        epoch = datetime.utcfromtimestamp(0)
        dt = datetime.utcnow() + 2 * JWT_EXPIRATION_DELTA
        exp = int((dt - epoch).total_seconds())
        self.user.user_profile.portals.add(self.portal)
        token = JWTView.get_token(self.user, self.portal, exp)
        expected_payload = {'username': self.user.username, 'exp': exp}
        actual_payload = jwt.decode(token, self.portal.sso_secret)
        self.assertDictEqual(expected_payload, actual_payload)

    def test_token_with_exp_as_datetime(self):
        epoch = datetime.utcfromtimestamp(0)
        dt = datetime.utcnow() + 2 * JWT_EXPIRATION_DELTA
        exp = int((dt - epoch).total_seconds())
        self.user.user_profile.portals.add(self.portal)
        token = JWTView.get_token(self.user, self.portal, dt)
        expected_payload = {'username': self.user.username, 'exp': exp}
        actual_payload = jwt.decode(token, self.portal.sso_secret)
        self.assertDictEqual(expected_payload, actual_payload)

    def test_token_with_default_exp(self):
        self.user.user_profile.portals.add(self.portal)
        token = JWTView.get_token(self.user, self.portal)
        expected_payload = {'username': self.user.username}
        actual_payload = jwt.decode(token, self.portal.sso_secret)
        self.assertTrue(isinstance(actual_payload.pop('exp'), int))
        self.assertDictEqual(expected_payload, actual_payload)

    @raises(ExpiredSignatureError)
    def test_expired_token(self):
        self.user.user_profile.portals.add(self.portal)
        token = JWTView.get_token(self.user, self.portal, 0)
        jwt.decode(token, self.portal.sso_secret)

    def test_get_request_with_invalid_next_parameter(self):
        request = self.factory.get(
            reverse('lizard_auth_server.jwt'), {
                'portal': self.portal.sso_key,
                'next': fake.uri_path(),
            },
        )
        self.user.user_profile.portals.add(self.portal)
        request.user = self.user
        response = JWTView.as_view()(request)
        expected_status_code = 400
        actual_status_code = response.status_code
        self.assertEqual(expected_status_code, actual_status_code)

    def test_get_request_without_portal_parameters(self):
        request = self.factory.get(
            reverse('lizard_auth_server.jwt'),
        )
        self.user.user_profile.portals.add(self.portal)
        request.user = self.user
        response = JWTView.as_view()(request)
        expected_status_code = 400
        actual_status_code = response.status_code
        self.assertEqual(expected_status_code, actual_status_code)

    def test_get_request_with_invalid_portal_parameter(self):
        random_sso_key = GenKey('Portal', 'sso_key')
        request = self.factory.get(
            reverse('lizard_auth_server.jwt'), {
                'portal': random_sso_key,
            },
        )
        self.user.user_profile.portals.add(self.portal)
        request.user = self.user
        response = JWTView.as_view()(request)
        expected_status_code = 400
        actual_status_code = response.status_code
        self.assertEqual(expected_status_code, actual_status_code)

    def test_get_request_without_portal_access(self):
        request = self.factory.get(
            reverse('lizard_auth_server.jwt'), {
                'portal': self.portal.sso_key,
            },
        )
        request.user = self.user
        response = JWTView.as_view()(request)
        expected_status_code = 400
        actual_status_code = response.status_code
        self.assertEqual(expected_status_code, actual_status_code)

    def test_get_request_as_anonymous_user(self):
        request = self.factory.get(
            reverse('lizard_auth_server.jwt'), {
                'portal': self.portal.sso_key,
            },
        )
        request.user = AnonymousUser()
        response = JWTView.as_view()(request)
        expected_status_code = 302
        actual_status_code = response.status_code
        self.assertEqual(expected_status_code, actual_status_code)
        expected_url = reverse('django.contrib.auth.views.login')
        self.assertTrue(response.url.startswith(expected_url))

    def test_get_request_with_text_response(self):
        request = self.factory.get(
            reverse('lizard_auth_server.jwt'), {
                'portal': self.portal.sso_key,
            },
        )
        self.user.user_profile.portals.add(self.portal)
        request.user = self.user
        response = JWTView.as_view()(request)
        expected_status_code = 200
        actual_status_code = response.status_code
        self.assertEqual(expected_status_code, actual_status_code)
        expected_content_type = 'text/plain'
        actual_content_type = response.get('Content-Type')
        self.assertEqual(expected_content_type, actual_content_type)
        token = response.content
        payload = jwt.decode(token, self.portal.sso_secret)
        self.assertTrue(payload['username'] == self.user.username)
        self.assertTrue('exp' in payload)

    def test_get_request_with_redirect_response(self):
        next_ = fake.url()
        request = self.factory.get(
            reverse('lizard_auth_server.jwt'), {
                'portal': self.portal.sso_key,
                'next': next_,
            },
        )
        self.user.user_profile.portals.add(self.portal)
        request.user = self.user
        response = JWTView.as_view()(request)
        expected_status_code = 302
        actual_status_code = response.status_code
        self.assertEqual(expected_status_code, actual_status_code)
        self.assertTrue(JWTView.is_url(response.url))
        self.assertTrue(response.url.startswith(next_))
        self.assertTrue('access_token=' in response.url)
