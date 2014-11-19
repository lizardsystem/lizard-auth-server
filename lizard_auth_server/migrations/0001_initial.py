# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import lizard_auth_server.models
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Invitation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=255)),
                ('email', models.EmailField(max_length=75)),
                ('organisation', models.CharField(max_length=255)),
                ('language', models.CharField(max_length=16)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('activation_key', models.CharField(max_length=64, unique=True, null=True, blank=True)),
                ('activation_key_date', models.DateTimeField(help_text='Date on which the activation key was generated. Used for expiration.', null=True, blank=True)),
                ('is_activated', models.BooleanField(default=False)),
                ('activated_on', models.DateTimeField(null=True, blank=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Organisation',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=255)),
                ('unique_id', models.CharField(default=lizard_auth_server.models.create_new_uuid, unique=True, max_length=32)),
            ],
            options={
                'ordering': ['name'],
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='OrganisationRole',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('for_all_users', models.BooleanField(default=False)),
                ('organisation', models.ForeignKey(to='lizard_auth_server.Organisation')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Portal',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(help_text='Name used to refer to this portal.', max_length=255)),
                ('sso_secret', models.CharField(default=lizard_auth_server.models.gen_key, help_text='Secret shared between SSO client and server to sign/encrypt communication.', unique=True, max_length=64)),
                ('sso_key', models.CharField(default=lizard_auth_server.models.gen_key, help_text='String used to identify the SSO client.', unique=True, max_length=64)),
                ('redirect_url', models.CharField(help_text='URL used in the SSO redirection.', max_length=255)),
                ('visit_url', models.CharField(help_text='URL used in the UI to refer to this portal.', max_length=255)),
            ],
            options={
                'ordering': ('name',),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('unique_id', models.CharField(default=lizard_auth_server.models.create_new_uuid, unique=True, max_length=32)),
                ('code', models.CharField(max_length=255)),
                ('name', models.CharField(max_length=255)),
                ('external_description', models.TextField()),
                ('internal_description', models.TextField()),
                ('portal', models.ForeignKey(to='lizard_auth_server.Portal')),
            ],
            options={
                'ordering': ['portal', 'name'],
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Token',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('request_token', models.CharField(unique=True, max_length=64)),
                ('auth_token', models.CharField(unique=True, max_length=64)),
                ('created', models.DateTimeField(default=lizard_auth_server.models.current_time_utc)),
                ('portal', models.ForeignKey(to='lizard_auth_server.Portal')),
                ('user', models.ForeignKey(to=settings.AUTH_USER_MODEL, null=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('title', models.CharField(default='', max_length=255, null=True, blank=True)),
                ('street', models.CharField(default='', max_length=255, null=True, blank=True)),
                ('postal_code', models.CharField(default='', max_length=255, null=True, blank=True)),
                ('town', models.CharField(default='', max_length=255, null=True, blank=True)),
                ('phone_number', models.CharField(default='', max_length=255, null=True, blank=True)),
                ('mobile_phone_number', models.CharField(default='', max_length=255, null=True, blank=True)),
                ('organisations', models.ManyToManyField(to='lizard_auth_server.Organisation', null=True, blank=True)),
                ('portals', models.ManyToManyField(to='lizard_auth_server.Portal', blank=True)),
                ('roles', models.ManyToManyField(to='lizard_auth_server.OrganisationRole', null=True, blank=True)),
                ('user', models.OneToOneField(to=settings.AUTH_USER_MODEL)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='role',
            unique_together=set([('name', 'portal')]),
        ),
        migrations.AddField(
            model_name='organisationrole',
            name='role',
            field=models.ForeignKey(to='lizard_auth_server.Role'),
            preserve_default=True,
        ),
        migrations.AlterUniqueTogether(
            name='organisationrole',
            unique_together=set([('organisation', 'role')]),
        ),
        migrations.AddField(
            model_name='organisation',
            name='roles',
            field=models.ManyToManyField(to='lizard_auth_server.Role', through='lizard_auth_server.OrganisationRole', blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='invitation',
            name='portals',
            field=models.ManyToManyField(to='lizard_auth_server.Portal', blank=True),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='invitation',
            name='user',
            field=models.ForeignKey(blank=True, to=settings.AUTH_USER_MODEL, null=True),
            preserve_default=True,
        ),
    ]
