from django.db.models.signals import post_save
from django.contrib.auth.models import User
from django.dispatch import receiver

from lizard_auth_server.models import UserProfile, Profile


# have the creation of a User trigger the creation of a UserProfile and
# Profile. The receiver decorator makes the signal connection.
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)
        Profile.objects.create(user=instance)

# post_save.connect(create_user_profile, sender=User)
