# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('lizard_auth_server', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserGroup',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=100)),
                ('organisation', models.ForeignKey(to='lizard_auth_server.Organisation')),
                ('roles', models.ManyToManyField(to='lizard_auth_server.Role')),
                ('user_profiles', models.ManyToManyField(to='lizard_auth_server.UserProfile')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AlterUniqueTogether(
            name='usergroup',
            unique_together=set([('name', 'organisation')]),
        ),
    ]
