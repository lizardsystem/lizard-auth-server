import uuid

from django.test import Client
from django.test import TestCase
from itsdangerous import URLSafeTimedSerializer
from lizard_auth_server import models
from lizard_auth_server import views_sso

from . import test_models


class TestConstructOrganisationRoleDict(TestCase):
    def test_empy_iterable(self):
        self.assertEquals(
            views_sso.construct_organisation_role_dict([]),
            {'organisations': [], 'roles': [], 'organisation_roles': []})

    def test_single_organisation_role(self):
        u_org = uuid.uuid4().hex
        u_role = uuid.uuid4().hex

        org = test_models.OrganisationF.build(
            name='testorg', unique_id=u_org)
        role = test_models.RoleF.build(
            unique_id=u_role,
            code='testrole',
            name='Testrole',
            external_description='The best role ever',
            internal_description="Except for our competitors")

        orgrole = models.OrganisationRole(
            organisation=org, role=role)

        self.assertEquals(
            views_sso.construct_organisation_role_dict([orgrole]), {
                'organisations': [{
                    'name': 'testorg',
                    'unique_id': u_org
                }],
                'roles': [{
                    'unique_id': u_role,
                    'code': 'testrole',
                    'name': 'Testrole',
                    'external_description': 'The best role ever',
                    'internal_description': 'Except for our competitors'
                }],
                'organisation_roles': [
                    [u_org, u_role]
                ]})


class TestLoginRedirect(TestCase):
    def setUp(self):
        self.username = 'me'
        self.password = 'your_mommie'
        self.key = 'secret_key'
        redirect = 'http://default.portal.net'
        allowed_domain = 'custom.net'

        self.client = Client()

        self.portal = test_models.PortalF.create(
            sso_key=self.key,
            redirect_url=redirect,
            allowed_domain=allowed_domain
        )
        user = test_models.UserF.create(username=self.username)
        user.set_password(self.password)
        user.save()

        org = test_models.OrganisationF.create(name='Some org')
        role = test_models.RoleF.create(portal=self.portal)

        models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)
        profile.portals.add(self.portal)

    def authorize_and_check_redirect(self, domain, redirect):
        request_token = 'request_token'
        auth_token = 'auth_token'

        token = test_models.TokenF.create(request_token=request_token,
                                          auth_token=auth_token,
                                          portal=self.portal)

        msg = {'request_token': request_token,
               'key': self.key,
               'domain': domain}
        message = URLSafeTimedSerializer(self.portal.sso_secret).dumps(msg)
        params = {'key': self.key, 'message': message}
        response = self.client.get('/sso/authorize/', params)
        self.assertEquals(response.status_code, 302)

        msg = {'request_token': request_token, 'auth_token': auth_token}
        message = URLSafeTimedSerializer(self.portal.sso_secret).dumps(msg)
        expec = '{}{}?message={}'.format(redirect,
                                         '/sso/local_login/',
                                         message)
        self.assertEquals(response.url, expec)

        token.delete()

    def test_login_redirect(self):
        params = {
            'username': self.username,
            'password': self.password,
            'next': '/sso/authorize'
        }
        response = self.client.post('/accounts/login/', params)

        self.assertEquals(response.status_code, 302)
        self.assertEquals(response.url, 'http://testserver/sso/authorize')

        self.authorize_and_check_redirect(None, self.portal.redirect_url)
        self.authorize_and_check_redirect('/', self.portal.redirect_url)
        self.authorize_and_check_redirect('/this_is_fine.html',
                                          self.portal.redirect_url)
        self.authorize_and_check_redirect('http://bad.com/wrong.aspx',
                                          self.portal.redirect_url)
        self.authorize_and_check_redirect('http://very.custom.net/ok',
                                          'http://very.custom.net')
        self.portal.allowed_domain = ''
        self.portal.save()
        self.authorize_and_check_redirect('http://very.custom.net/nok',
                                          self.portal.redirect_url)
