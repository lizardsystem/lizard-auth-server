import uuid

from django.test import Client
from django.test import TestCase
from itsdangerous import URLSafeTimedSerializer
from lizard_auth_server import models
from lizard_auth_server import views_sso
from lizard_auth_server.tests import factories


class TestConstructOrganisationRoleDict(TestCase):
    def test_empy_iterable(self):
        self.assertEquals(
            views_sso.construct_organisation_role_dict([]),
            {'organisations': [], 'roles': [], 'organisation_roles': []})

    def test_single_organisation_role(self):
        u_org = uuid.uuid4().hex
        u_role = uuid.uuid4().hex

        # TODO: used create instead of build because we need the orgrole
        # to be saveable. Better solution: make an orgrole factory which
        # has a primary key or something?
        org = factories.OrganisationF.create(
            name='testorg', unique_id=u_org)
        role = factories.RoleF.create(
            unique_id=u_role,
            code='testrole',
            name='Testrole',
            external_description='The best role ever',
            internal_description="Except for our competitors")

        orgrole = models.OrganisationRole(
            organisation=org, role=role)
        # TODO: the reason for this save is because orgroles need a primary
        # key to be hashable in Django >=1.7, and apparently it didn't need
        # one before.
        orgrole.save()

        org_role_dicts = views_sso.construct_organisation_role_dict([orgrole])

        self.assertEquals(org_role_dicts, {
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

        self.portal = factories.PortalF.create(
            sso_key=self.key,
            redirect_url=redirect,
            allowed_domain=allowed_domain
        )
        user = factories.UserF.create(username=self.username)
        user.set_password(self.password)
        user.save()

        org = factories.OrganisationF.create(name='Some org')
        role = factories.RoleF.create(portal=self.portal)

        models.OrganisationRole.objects.create(
            organisation=org, role=role, for_all_users=True)

        profile = models.UserProfile.objects.fetch_for_user(user)
        profile.organisations.add(org)
        profile.portals.add(self.portal)

    def authorize_and_check_redirect(self, domain, redirect):
        request_token = 'request_token'
        auth_token = 'auth_token'

        token = factories.TokenF.create(request_token=request_token,
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

        # Before upgrading from Django 1.6 -> 1.9 this used to be this (but now
        # doesn't work):
        # self.assertEquals(response.url, 'http://testserver/sso/authorize')
        self.assertEquals(response.url, '/sso/authorize')

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
