# -*- coding: utf-8 -*-
# Generated by Django 1.9.7 on 2016-08-24 14:37
from __future__ import unicode_literals
from django.db import migrations
from django.db import models


class Migration(migrations.Migration):

    dependencies = [
        ('lizard_auth_server', '0006_auto_20160824_1536'),
    ]

    operations = [
        migrations.AddField(
            model_name='portal',
            name='already_migrated',
            field=models.BooleanField(default=False, verbose_name='already migrated'),
        ),
    ]
