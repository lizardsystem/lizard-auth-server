# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-07-01 12:23
from django.conf import settings
from django.db import migrations
from django.db import models

import django.db.models.deletion
import lizard_auth_server.models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("lizard_auth_server", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="Company",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "name",
                    models.CharField(max_length=255, unique=True, verbose_name="name"),
                ),
                (
                    "unique_id",
                    models.CharField(
                        default=lizard_auth_server.models.create_new_uuid,
                        max_length=32,
                        unique=True,
                        verbose_name="unique id",
                    ),
                ),
            ],
            options={
                "verbose_name": "company",
                "verbose_name_plural": "companies",
            },
        ),
        migrations.CreateModel(
            name="Profile",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="created at"),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True, verbose_name="updated at"),
                ),
                (
                    "company",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        to="lizard_auth_server.Company",
                        verbose_name="company",
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="profile",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="user",
                    ),
                ),
            ],
            options={
                "verbose_name": "user profile",
                "verbose_name_plural": "user profiles",
            },
        ),
        migrations.CreateModel(
            name="Site",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "name",
                    models.CharField(
                        help_text="Name used to refer to this site.",
                        max_length=255,
                        verbose_name="name",
                    ),
                ),
                (
                    "sso_secret",
                    models.CharField(
                        default=lizard_auth_server.models.GenKey("Site", "sso_secret"),
                        help_text="Secret shared between SSO client and server to sign/encrypt communication.",
                        max_length=64,
                        unique=True,
                        verbose_name="shared secret",
                    ),
                ),
                (
                    "sso_key",
                    models.CharField(
                        default=lizard_auth_server.models.GenKey("Site", "sso_key"),
                        help_text="String used to identify the SSO client.",
                        max_length=64,
                        unique=True,
                        verbose_name="identifying key",
                    ),
                ),
                (
                    "allowed_domain",
                    models.CharField(
                        default="",
                        help_text="Allowed domain suffix for redirects using the next parameter. Multiple, whitespace-separated suffixes may be specified.",
                        max_length=1000,
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
                (
                    "available_to",
                    models.ManyToManyField(
                        blank=True,
                        related_name="sites",
                        to="lizard_auth_server.Company",
                        verbose_name="available to",
                    ),
                ),
            ],
            options={
                "verbose_name": "site",
                "verbose_name_plural": "sites",
            },
        ),
        migrations.AlterModelOptions(
            name="userprofile",
            options={
                "ordering": ["user__username"],
                "verbose_name": "user profile (old style)",
                "verbose_name_plural": "user profiles (old style)",
            },
        ),
        migrations.AddField(
            model_name="company",
            name="administrators",
            field=models.ManyToManyField(
                blank=True,
                help_text="Admins can add/edit users belonging to the company and can add/remove guests and manage site access",
                related_name="companies_as_admin",
                to="lizard_auth_server.Profile",
                verbose_name="administrators",
            ),
        ),
        migrations.AddField(
            model_name="company",
            name="guests",
            field=models.ManyToManyField(
                blank=True,
                help_text="Guests or external users.",
                related_name="companies_as_guest",
                to="lizard_auth_server.Profile",
                verbose_name="guests",
            ),
        ),
    ]
