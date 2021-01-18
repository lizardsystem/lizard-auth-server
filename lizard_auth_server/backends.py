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

import abc


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
            user.migrated_at = django.utils.timezone.now()
            user.save()

        return user


class AbstractCognitoBackend(ModelBackend):
    __metaclass__ = abc.ABCMeta

    UNAUTHORIZED_ERROR_CODE = "NotAuthorizedException"

    USER_NOT_FOUND_ERROR_CODE = "UserNotFoundException"

    COGNITO_USER_CLASS = CognitoUser

    @abc.abstractmethod
    def authenticate(self, username=None, password=None):
        """
        Authenticate a Cognito User
        :param username: Cognito username
        :param password: Cognito password
        :return: returns User instance of AUTH_USER_MODEL or None
        """
        cognito_user = CognitoUser(
            settings.COGNITO_USER_POOL_ID,
            settings.COGNITO_APP_ID,
            access_key=getattr(settings, "AWS_ACCESS_KEY_ID", None),
            secret_key=getattr(settings, "AWS_SECRET_ACCESS_KEY", None),
            username=username,
        )
        try:
            cognito_user.authenticate(password)
        except (Boto3Error, ClientError) as e:
            return self.handle_error_response(e)
        user = cognito_user.get_user()

        return user

    def handle_error_response(self, error):
        error_code = error.response["Error"]["Code"]
        if error_code in [
            AbstractCognitoBackend.UNAUTHORIZED_ERROR_CODE,
            AbstractCognitoBackend.USER_NOT_FOUND_ERROR_CODE,
        ]:
            return None
        raise error


class CognitoBackend(AbstractCognitoBackend):
    def authenticate(self, request, username=None, password=None):
        """
        Authenticate a Cognito User and store an access, ID and
        refresh token in the session.
        """
        user = super(CognitoBackend, self).authenticate(
            username=username, password=password
        )
        if user:
            request.session["ACCESS_TOKEN"] = user.access_token
            request.session["ID_TOKEN"] = user.id_token
            request.session["REFRESH_TOKEN"] = user.refresh_token
            request.session.save()
        return user
