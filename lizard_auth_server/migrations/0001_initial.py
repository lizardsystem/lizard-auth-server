# -*- coding: utf-8 -*-
from django.conf import settings
from django.db import migrations
from django.db import models

import lizard_auth_server.models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Invitation",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                ("name", models.CharField(max_length=255, verbose_name="name")),
                ("email", models.EmailField(max_length=254, verbose_name="e-mail")),
                (
                    "organisation",
                    models.CharField(max_length=255, verbose_name="organisation"),
                ),
                ("language", models.CharField(max_length=16, verbose_name="language")),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="created on"),
                ),
                (
                    "activation_key",
                    models.CharField(
                        max_length=64,
                        unique=True,
                        null=True,
                        verbose_name="activation key",
                        blank=True,
                    ),
                ),
                (
                    "activation_key_date",
                    models.DateTimeField(
                        help_text="Date on which the activation key was generated. Used for expiration.",
                        null=True,
                        verbose_name="activation key date",
                        blank=True,
                    ),
                ),
                (
                    "is_activated",
                    models.BooleanField(default=False, verbose_name="is activated"),
                ),
                (
                    "activated_on",
                    models.DateTimeField(
                        null=True, verbose_name="activated on", blank=True
                    ),
                ),
            ],
            options={
                "ordering": ["is_activated", "-created_at", "email"],
                "verbose_name": "invitation",
                "verbose_name_plural": "invitation",
            },
        ),
        migrations.CreateModel(
            name="Organisation",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "name",
                    models.CharField(unique=True, max_length=255, verbose_name="name"),
                ),
                (
                    "unique_id",
                    models.CharField(
                        default=lizard_auth_server.models.create_new_uuid,
                        unique=True,
                        max_length=32,
                        verbose_name="unique id",
                    ),
                ),
            ],
            options={
                "ordering": ["name"],
                "verbose_name": "organisation",
                "verbose_name_plural": "organisations",
            },
        ),
        migrations.CreateModel(
            name="OrganisationRole",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "for_all_users",
                    models.BooleanField(default=False, verbose_name="for all users"),
                ),
                (
                    "organisation",
                    models.ForeignKey(
                        related_name="organisation_roles",
                        verbose_name="organisation",
                        to="lizard_auth_server.Organisation",
                        on_delete=models.CASCADE,
                    ),
                ),
            ],
            options={
                "verbose_name": "organisation-role-mapping",
                "verbose_name_plural": "organisation-role-mappings",
            },
        ),
        migrations.CreateModel(
            name="Portal",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        help_text="Name used to refer to this portal.",
                        max_length=255,
                        verbose_name="name",
                    ),
                ),
                (
                    "sso_secret",
                    models.CharField(
                        default=lizard_auth_server.models.GenKey(
                            "Portal", "sso_secret"
                        ),
                        help_text="Secret shared between SSO client and server to sign/encrypt communication.",
                        unique=True,
                        max_length=64,
                        verbose_name="shared secret",
                    ),
                ),
                (
                    "sso_key",
                    models.CharField(
                        default=lizard_auth_server.models.GenKey("Portal", "sso_key"),
                        help_text="String used to identify the SSO client.",
                        unique=True,
                        max_length=64,
                        verbose_name="identifying key",
                    ),
                ),
                (
                    "allowed_domain",
                    models.CharField(
                        default="",
                        help_text="Allowed domain suffix for redirects using the next parameter. Multiple, whitespace-separated suffixes may be specified.",
                        max_length=255,
                        verbose_name="allowed domain(s)",
                    ),
                ),
                (
                    "redirect_url",
                    models.CharField(
                        help_text="URL used in the SSO redirection.",
                        max_length=255,
                        verbose_name="redirect url",
                    ),
                ),
                (
                    "visit_url",
                    models.CharField(
                        help_text="URL used in the UI to refer to this portal.",
                        max_length=255,
                        verbose_name="visit url",
                    ),
                ),
            ],
            options={
                "ordering": ("name",),
                "verbose_name": "portal",
                "verbose_name_plural": "portals",
            },
        ),
        migrations.CreateModel(
            name="Role",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "unique_id",
                    models.CharField(
                        default=lizard_auth_server.models.create_new_uuid,
                        verbose_name="unique id",
                        unique=True,
                        max_length=32,
                        editable=False,
                    ),
                ),
                (
                    "code",
                    models.CharField(
                        help_text="name used internally by the portal to identify the role",
                        max_length=255,
                        verbose_name="code",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        help_text="human-readable name",
                        max_length=255,
                        verbose_name="name",
                    ),
                ),
                (
                    "external_description",
                    models.TextField(verbose_name="external description", blank=True),
                ),
                (
                    "internal_description",
                    models.TextField(verbose_name="internal description", blank=True),
                ),
                (
                    "inheriting_roles",
                    models.ManyToManyField(
                        help_text="roles that are automatically inherited from us for organisations that have organisation roles pointing at both base and inheriting role.",
                        related_name="base_roles",
                        verbose_name="inheriting roles",
                        to="lizard_auth_server.Role",
                        blank=True,
                    ),
                ),
                (
                    "portal",
                    models.ForeignKey(
                        related_name="roles",
                        verbose_name="portal",
                        to="lizard_auth_server.Portal",
                        on_delete=models.CASCADE,
                    ),
                ),
            ],
            options={
                "ordering": ["portal", "name"],
                "verbose_name": "role",
                "verbose_name_plural": "roles",
            },
        ),
        migrations.CreateModel(
            name="Token",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "request_token",
                    models.CharField(
                        unique=True, max_length=64, verbose_name="request token"
                    ),
                ),
                (
                    "auth_token",
                    models.CharField(
                        unique=True, max_length=64, verbose_name="auth token"
                    ),
                ),
                (
                    "created",
                    models.DateTimeField(
                        default=lizard_auth_server.models.token_creation_date,
                        verbose_name="created on",
                    ),
                ),
                (
                    "portal",
                    models.ForeignKey(
                        verbose_name="portal",
                        to="lizard_auth_server.Portal",
                        on_delete=models.CASCADE,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        verbose_name="user",
                        blank=True,
                        to=settings.AUTH_USER_MODEL,
                        null=True,
                        on_delete=models.CASCADE,
                    ),
                ),
            ],
            options={
                "ordering": ("-created",),
                "verbose_name": "authentication token",
                "verbose_name_plural": "authentication tokens",
            },
        ),
        migrations.CreateModel(
            name="UserProfile",
            fields=[
                (
                    "id",
                    models.AutoField(
                        verbose_name="ID",
                        serialize=False,
                        auto_created=True,
                        primary_key=True,
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="created on"),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True, verbose_name="updated on"),
                ),
                (
                    "title",
                    models.CharField(
                        default="",
                        max_length=255,
                        null=True,
                        verbose_name="title",
                        blank=True,
                    ),
                ),
                (
                    "street",
                    models.CharField(
                        default="",
                        max_length=255,
                        null=True,
                        verbose_name="street",
                        blank=True,
                    ),
                ),
                (
                    "postal_code",
                    models.CharField(
                        default="",
                        max_length=255,
                        null=True,
                        verbose_name="postal code",
                        blank=True,
                    ),
                ),
                (
                    "town",
                    models.CharField(
                        default="",
                        max_length=255,
                        null=True,
                        verbose_name="town",
                        blank=True,
                    ),
                ),
                (
                    "phone_number",
                    models.CharField(
                        default="",
                        max_length=255,
                        null=True,
                        verbose_name="phone number",
                        blank=True,
                    ),
                ),
                (
                    "mobile_phone_number",
                    models.CharField(
                        default="",
                        max_length=255,
                        null=True,
                        verbose_name="mobile phone number",
                        blank=True,
                    ),
                ),
                (
                    "organisations",
                    models.ManyToManyField(
                        related_name="user_profiles",
                        null=True,
                        verbose_name="organisations",
                        to="lizard_auth_server.Organisation",
                        blank=True,
                    ),
                ),
                (
                    "portals",
                    models.ManyToManyField(
                        related_name="user_profiles",
                        verbose_name="portals",
                        to="lizard_auth_server.Portal",
                        blank=True,
                    ),
                ),
                (
                    "roles",
                    models.ManyToManyField(
                        related_name="user_profiles",
                        null=True,
                        verbose_name="roles (via organisation)",
                        to="lizard_auth_server.OrganisationRole",
                        blank=True,
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        related_name="user_profile",
                        verbose_name="user",
                        to=settings.AUTH_USER_MODEL,
                        on_delete=models.CASCADE,
                    ),
                ),
            ],
            options={
                "ordering": ["user__username"],
                "verbose_name": "user profile",
                "verbose_name_plural": "user profiles",
            },
        ),
        migrations.AddField(
            model_name="organisationrole",
            name="role",
            field=models.ForeignKey(
                related_name="organisation_roles",
                verbose_name="role",
                to="lizard_auth_server.Role",
                on_delete=models.CASCADE,
            ),
        ),
        migrations.AddField(
            model_name="organisation",
            name="roles",
            field=models.ManyToManyField(
                to="lizard_auth_server.Role",
                verbose_name="roles",
                through="lizard_auth_server.OrganisationRole",
                blank=True,
            ),
        ),
        migrations.AddField(
            model_name="invitation",
            name="portals",
            field=models.ManyToManyField(
                to="lizard_auth_server.Portal", verbose_name="portals", blank=True
            ),
        ),
        migrations.AddField(
            model_name="invitation",
            name="user",
            field=models.ForeignKey(
                verbose_name="user",
                blank=True,
                to=settings.AUTH_USER_MODEL,
                null=True,
                on_delete=models.CASCADE,
            ),
        ),
        migrations.AlterUniqueTogether(
            name="role",
            unique_together=set([("name", "portal")]),
        ),
        migrations.AlterUniqueTogether(
            name="organisationrole",
            unique_together=set([("organisation", "role")]),
        ),
    ]
