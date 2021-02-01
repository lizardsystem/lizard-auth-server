"""Custom Django authentication backend

Copyright note: copied almost verbatim from backend.py in
https://github.com/metametricsinc/django-warrant
(BSD licensed)

"""
from boto3.exceptions import Boto3Error
from botocore.exceptions import ClientError
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.utils.six import iteritems
from warrant import Cognito

import django.utils.timezone
import logging


logger = logging.getLogger(__name__)


def cognito_to_dict(attr_list, mapping):
    user_attrs = dict()
    for i in attr_list:
        name = mapping.get(i.get("Name"))
        if name:
            value = i.get("Value")
            user_attrs[name] = value
    return user_attrs


class CognitoUser(Cognito):
    user_class = get_user_model()
    # Mapping of Cognito User attribute name to Django User attribute name
    COGNITO_ATTR_MAPPING = getattr(
        settings,
        "COGNITO_ATTR_MAPPING",
        {
            "email": "email",
            "given_name": "first_name",
            "family_name": "last_name",
        },
    )

    @classmethod
    def from_username(cls, username):
        return cls(
            settings.COGNITO_USER_POOL_ID,
            settings.COGNITO_APP_ID,
            access_key=getattr(settings, "AWS_ACCESS_KEY_ID", None),
            secret_key=getattr(settings, "AWS_SECRET_ACCESS_KEY", None),
            client_secret=getattr(settings, "COGNITO_APP_SECRET", None),
            username=username,
        )

    def get_user_obj(self, username=None, attribute_list=[], metadata={}, attr_map={}):
        user_attrs = cognito_to_dict(attribute_list, CognitoUser.COGNITO_ATTR_MAPPING)
        django_fields = [f.name for f in CognitoUser.user_class._meta.get_fields()]
        extra_attrs = {}
        for k, v in user_attrs.items():
            if k not in django_fields:
                extra_attrs.update({k: user_attrs.pop(k, None)})

        # The original code used COGNITO_CREATE_UNKNOWN_USERS, but in our case
        # we always need the user (for the local session) so we always create
        # it if missing. There's no update of attributes as we don't care
        # about that after migration to cognito. We *do* set ``migrated_at``.
        user, created = CognitoUser.user_class.objects.get_or_create(username=username)
        if created:
            logger.info("Created local user %s as they exist on cognito.", user)
            for k, v in iteritems(user_attrs):
                setattr(user, k, v)
            user.user_profile.migrated_at = django.utils.timezone.now()
            user.user_profile.save()

        return user

    def admin_set_user_password(self, password):
        self.client.admin_set_user_password(
            UserPoolId=self.user_pool_id,
            Username=self.username,
            Permanent=True,
            Password=password,
        )


class CognitoBackend(ModelBackend):

    UNAUTHORIZED_ERROR_CODE = "NotAuthorizedException"

    USER_NOT_FOUND_ERROR_CODE = "UserNotFoundException"

    COGNITO_USER_CLASS = CognitoUser

    def authenticate(self, username=None, password=None):
        """
        Authenticate a Cognito User
        :param username: Cognito username
        :param password: Cognito password
        :return: returns User instance of AUTH_USER_MODEL or None
        """
        cognito_user = CognitoUser.from_username(username)
        try:
            cognito_user.admin_authenticate(password)
            # ^^^ This uses ADMIN_NO_SRP_AUTH, but that's the old name for
            # ADMIN_USER_PASSWORD_AUTH (which we need), so it will probably be
            # OK.
        except (Boto3Error, ClientError) as e:
            return self.handle_error_response(e)
        user = cognito_user.get_user()

        return user

    def handle_error_response(self, error):
        error_code = error.response["Error"]["Code"]
        if error_code in [
            CognitoBackend.UNAUTHORIZED_ERROR_CODE,
            CognitoBackend.USER_NOT_FOUND_ERROR_CODE,
        ]:
            return None
        raise error
