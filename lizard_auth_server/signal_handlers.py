from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db.models.signals import post_save
from django.db.models.signals import pre_save
from django.dispatch import receiver
from lizard_auth_server.backends import CognitoUser
from lizard_auth_server.models import UserProfile


# Have the creation of a User fail if it exists in Cognito
@receiver(pre_save, sender=User)
def check_user_exists(sender, instance, **kwargs):
    if not getattr(settings, "AWS_ACCESS_KEY_ID", None):
        return  # do nothing if AWS is not configured

    if instance.pk is not None:
        return  # do nothing if it is an update to an existing user

    cognito_user = CognitoUser.from_username(instance.username)
    if cognito_user.admin_user_exists():
        raise ValidationError("This username is already taken.")


# Have the creation of a User trigger the creation of a UserProfile.
# The receiver decorator makes the signal connection.
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
