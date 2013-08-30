import uuid

from django.test import TestCase

from . import test_models
from lizard_auth_server import models
from lizard_auth_server import views_sso


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
            views_sso.construct_organisation_role_dict([orgrole]),
            {'organisations': [{
                        'name': 'testorg',
                        'unique_id': u_org
                        }],
             'roles': [{
                        'unique_id': u_role,
                        'code': 'testrole',
                        'name': 'Testrole',
                        'external_description': 'The best role ever',
                        'internal_description': 'Except for our competitors'}
                        ],
             'organisation_roles': [
                    [u_org, u_role]
                    ]})
