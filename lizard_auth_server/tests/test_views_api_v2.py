import datetime
import jwt
import mock

from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.forms import ValidationError
from django.test import Client
from django.test import TestCase
from django.test.client import RequestFactory
from lizard_auth_server import views_api_v2
from lizard_auth_server.tests import factories


class TestStartView(TestCase):

    def test_smoke(self):
        client = Client()
        result = client.get(
            reverse('lizard_auth_server.api_v2.start'))
        self.assertEquals(200, result.status_code)

    def test_url_includes_host(self):
        response = self.client.get('https://some.server/api2/')
        self.assertIn('http', str(response.content))


class TestCheckCredentialsView(TestCase):
    def setUp(self):
        self.sso_key = 'sso key'
        factories.PortalF.create(sso_key=self.sso_key)
        self.view = views_api_v2.CheckCredentialsView()
        self.request_factory = RequestFactory()
        self.some_request = self.request_factory.get('/some/url/')
        self.organisation = factories.OrganisationF()
        self.username = 'reinout'
        self.password = 'annie'
        self.user = factories.UserF(username=self.username,
                                    password=self.password)

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
        form = mock.Mock()
        form.cleaned_data = {'iss': self.sso_key,
                             'username': self.username,
                             'password': self.password}

        result = self.view.form_valid(form)
        self.assertEquals(200, result.status_code)

    def test_invalid_login(self):
        form = mock.Mock()
        form.cleaned_data = {'iss': self.sso_key,
                             'username': 'pietje',
                             'password': 'ikkanniettypen'}
        self.assertRaises(PermissionDenied, self.view.form_valid, form)


class TestLoginRedirectV2(TestCase):
    """Test the V2 API redirects"""
    def setUp(self):
        self.username = 'me'
        self.password = 'bla'
        self.sso_key = 'ssokey'
        self.secret_key = 'a secret'

        self.client = Client()

        user = factories.UserF.create(username=self.username)
        user.set_password(self.password)
        user.save()
        self.user_profile = factories.UserProfileF(user=user)

        self.portal = factories.PortalF.create(
            sso_key=self.sso_key,
            sso_secret=self.secret_key,
        )
        self.portal.save()

        self.payload = {
            'iss': self.sso_key,
            'login_success_url': 'http://very.custom.net/sso/local_login/',
            }
        self.message = jwt.encode(self.payload,
                                  self.secret_key,
                                  algorithm='HS256')

    def test_login_redirect(self):
        params = {
            'username': self.username,
            'password': self.password,
            'next': '/api2/login/'
        }
        resp1 = self.client.post('/accounts/login/', params)
        self.assertEquals(resp1.status_code, 302)

        jwt_params = {
            'key': self.sso_key,
            'message': self.message,
            }
        self.assertEqual(resp1.url, '/api2/login/')

        resp2 = self.client.get('/api2/login/', jwt_params)
        self.assertEqual(resp2.status_code, 302)
        print(resp2.url)
        self.assertTrue(
            'http://very.custom.net/sso/local_login/' in resp2.url)

    # Note: does the test below really belong here? [reinout 2016-09-21]
    def test_inactive_user_cant_login(self):
        self.user_profile.user.is_active = False
        self.user_profile.user.save()

        params = {
            'username': self.username,
            'password': self.password,
            'next': '/api2/login/'
        }
        resp1 = self.client.post('/accounts/login/', params)
        # Basically this means that the redirect failed and the user couldn't
        # log in, which is in line with what we expect with an inactive user.
        self.assertTrue(resp1.status_code != 302)
        self.assertEqual(resp1.status_code, 200)


class TestLogoutViewV2(TestCase):
    """Test the V2 API logout"""
    def setUp(self):
        self.username = 'me'
        self.password = 'bla'
        self.sso_key = 'ssokey'
        self.secret_key = 'a secret'
        redirect = 'http://default.portal.net'
        allowed_domain = 'custom.net'

        self.client = Client()

        user = factories.UserF.create(username=self.username)
        user.set_password(self.password)
        user.save()
        self.user_profile = factories.UserProfileF(user=user)

        self.portal = factories.PortalF.create(
            sso_key=self.sso_key,
            sso_secret=self.secret_key,
            redirect_url=redirect,
            allowed_domain=allowed_domain,
        )
        self.portal.save()

        self.payload = {
            'iss': self.sso_key,
            'logout_url': 'http://very.custom.net/sso/logout/',
            }
        self.message = jwt.encode(self.payload,
                                  self.secret_key,
                                  algorithm='HS256')

    def test_logout_with_missing_param(self):
        faulty_message = jwt.encode({'iss': self.sso_key},
                                    self.secret_key,
                                    algorithm='HS256')
        params = {
            'key': self.sso_key,
            'message': faulty_message
        }
        self.assertRaises(ValidationError,
                          self.client.get,
                          '/api2/logout/',
                          params)

    def test_logout_phase_one(self):
        params = {
            'key': self.sso_key,
            'message': self.message
        }
        response = self.client.get('/api2/logout/', params)
        self.assertEqual(response.status_code, 302)
        print(response.url)
        self.assertTrue(
            '/accounts/logout/' in response.url)
        self.assertTrue(
            'key%3Dssokey' in response.url)

    def test_logout_phase_two(self):
        params = {
            'key': self.sso_key,
            'message': self.message
        }
        response = self.client.get('/api2/logout_redirect_back_to_portal/',
                                   params)
        self.assertEqual(response.status_code, 302)
        self.assertEqual('http://very.custom.net/sso/logout/',
                         response.url)


class TestNewUserView(TestCase):
    def setUp(self):
        self.view = views_api_v2.NewUserView()
        sso_key = 'sso key'
        factories.PortalF.create(sso_key=sso_key)
        self.request_factory = RequestFactory()
        self.some_request = self.request_factory.get(
            'http://some.site/some/url/')
        self.user_data = {'iss': sso_key,
                          'username': 'pietje',
                          'email': 'pietje@klaasje.test.com',
                          'first_name': 'pietje',
                          'last_name': 'klaasje'}

    def test_disallowed_get(self):
        client = Client()
        result = client.get(
            reverse('lizard_auth_server.api_v2.new_user'))
        self.assertEquals(405, result.status_code)

    def test_new_user(self):
        form = mock.Mock()
        form.cleaned_data = self.user_data
        self.view.request = self.some_request
        result = self.view.form_valid(form)
        self.assertEquals(201, result.status_code)
        self.assertTrue(User.objects.get(username='pietje'))

    def test_new_user_starts_inactive(self):
        form = mock.Mock()
        form.cleaned_data = self.user_data
        self.view.request = self.some_request
        self.view.form_valid(form)
        self.assertFalse(User.objects.get(username='pietje').is_active)

    def test_new_user_sends_email(self):
        form = mock.Mock()
        form.cleaned_data = self.user_data
        self.view.request = self.some_request
        with mock.patch(
                'lizard_auth_server.views_api_v2.send_mail') as mocked:
            self.view.form_valid(form)
            arguments = mocked.call_args[0]
            print(arguments)
            message = arguments[1]
            self.assertIn('sso%20key', message)

    def test_exiting_user(self):
        factories.UserF(email='pietje@klaasje.test.com')
        form = mock.Mock()
        form.cleaned_data = self.user_data
        result = self.view.form_valid(form)
        self.assertEquals(200, result.status_code)

    def test_exiting_user_duplicate_email(self):
        factories.UserF(email='pietje@klaasje.test.com')
        factories.UserF(email='pietje@klaasje.test.com')
        form = mock.Mock()
        form.cleaned_data = self.user_data
        result = self.view.form_valid(form)
        self.assertEquals(200, result.status_code)

    def test_duplicate_username(self):
        factories.UserF(username='pietje',
                        email='nietpietje@example.com')
        form = mock.Mock()
        form.cleaned_data = self.user_data
        self.assertRaises(ValidationError,
                          self.view.form_valid,
                          form)

    def test_duplicate_username_http_response(self):
        client = Client()
        params = {'username': 'pietje',
                  'email': 'nietpietje@example.com',
                  'first_name': 'pietje',
                  'last_name': 'pietje',
              }
        response = client.post(
            reverse('lizard_auth_server.api_v2.new_user'), params)
        self.assertEquals(400, response.status_code)


class TestActivateAndSetPasswordView(TestCase):

    def setUp(self):
        self.user = factories.UserF.create()
        self.user.set_unusable_password()
        self.user.is_active = False
        self.user.save()
        self.portal = factories.PortalF.create()
        # Mimick url creation. See create_and_mail_user()
        key = self.portal.sso_key
        expiration = datetime.datetime.utcnow() + datetime.timedelta(
            days=1)
        payload = {'aud': key,
                   'exp': expiration,
                   'user_id': self.user.id}
        signed_message = jwt.encode(payload,
                                    self.portal.sso_secret,
                                    algorithm='HS256')
        self.activation_url = reverse(
            'lizard_auth_server.api_v2.activate-and-set-password',
            kwargs={'user_id': self.user.id,
                    'sso_key': key,
                    'message': signed_message})

    def test_get_smoke(self):
        client = Client()
        response = client.get(self.activation_url)
        self.assertEquals(200, response.status_code)

    def test_post_smoke(self):
        client = Client()
        response = client.post(self.activation_url,
                               {'new_password1': 'Pietje123',
                                'new_password2': 'Pietje123'})
        self.assertEquals(302, response.status_code)

    def test_user_activated(self):
        client = Client()
        client.post(self.activation_url,
                    {'new_password1': 'Pietje123',
                     'new_password2': 'Pietje123'})
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertTrue(self.user.has_usable_password())


class TestActivatedGoToPortalView(TestCase):

    def setUp(self):
        self.portal = factories.PortalF.create()

    def test_smoke(self):
        client = Client()
        response = client.get('/api2/activated/%s/' % self.portal.id)
        self.assertEquals(200, response.status_code)


class TestOrganisationsView(TestCase):

    def setUp(self):
        sso_key = 'ssokey'
        secret_key = 'a secret'
        factories.PortalF.create(
            sso_key=sso_key,
            sso_secret=secret_key,
        )

        payload = {'iss': sso_key}
        message = jwt.encode(payload,
                             secret_key,
                             algorithm='HS256')
        self.jwt_params = {
            'key': sso_key,
            'message': message,
        }

    def test_unauthenticated_denied(self):
        # You need an sso key (=an empty jwt message)
        response = self.client.get('/api2/organisations/')
        self.assertEquals(400, response.status_code)

    def test_smoke(self):
        response = self.client.get('/api2/organisations/',
                                   self.jwt_params)
        self.assertEquals(200, response.status_code)

    def test_result(self):
        factories.OrganisationF(name="Signalmanufaktur Neuwitz")
        response = self.client.get('/api2/organisations/',
                                   self.jwt_params)
        self.assertIn('Neuwitz', str(response.content))
