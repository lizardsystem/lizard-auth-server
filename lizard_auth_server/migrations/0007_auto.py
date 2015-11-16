# -*- coding: utf-8 -*-
from south.utils import datetime_utils as datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Removing M2M table for field child_roles on 'Role'
        db.delete_table(db.shorten_name(u'lizard_auth_server_role_child_roles'))

        # Adding M2M table for field inheriting_roles on 'Role'
        m2m_table_name = db.shorten_name(u'lizard_auth_server_role_inheriting_roles')
        db.create_table(m2m_table_name, (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('from_role', models.ForeignKey(orm[u'lizard_auth_server.role'], null=False)),
            ('to_role', models.ForeignKey(orm[u'lizard_auth_server.role'], null=False))
        ))
        db.create_unique(m2m_table_name, ['from_role_id', 'to_role_id'])


    def backwards(self, orm):
        # Adding M2M table for field child_roles on 'Role'
        m2m_table_name = db.shorten_name(u'lizard_auth_server_role_child_roles')
        db.create_table(m2m_table_name, (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('from_role', models.ForeignKey(orm[u'lizard_auth_server.role'], null=False)),
            ('to_role', models.ForeignKey(orm[u'lizard_auth_server.role'], null=False))
        ))
        db.create_unique(m2m_table_name, ['from_role_id', 'to_role_id'])

        # Removing M2M table for field inheriting_roles on 'Role'
        db.delete_table(db.shorten_name(u'lizard_auth_server_role_inheriting_roles'))


    models = {
        u'auth.group': {
            'Meta': {'object_name': 'Group'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        u'auth.permission': {
            'Meta': {'ordering': "(u'content_type__app_label', u'content_type__model', u'codename')", 'unique_together': "((u'content_type', u'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['contenttypes.ContentType']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        u'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Group']"}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_set'", 'blank': 'True', 'to': u"orm['auth.Permission']"}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        u'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        u'lizard_auth_server.invitation': {
            'Meta': {'ordering': "[u'is_activated', u'-created_at', u'email']", 'object_name': 'Invitation'},
            'activated_on': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'activation_key': ('django.db.models.fields.CharField', [], {'max_length': '64', 'unique': 'True', 'null': 'True', 'blank': 'True'}),
            'activation_key_date': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'created_at': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_activated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'language': ('django.db.models.fields.CharField', [], {'max_length': '16'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'organisation': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'portals': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['lizard_auth_server.Portal']", 'symmetrical': 'False', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']", 'null': 'True', 'blank': 'True'})
        },
        u'lizard_auth_server.organisation': {
            'Meta': {'ordering': "[u'name']", 'object_name': 'Organisation'},
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '255'}),
            'roles': ('django.db.models.fields.related.ManyToManyField', [], {'to': u"orm['lizard_auth_server.Role']", 'symmetrical': 'False', 'through': u"orm['lizard_auth_server.OrganisationRole']", 'blank': 'True'}),
            'unique_id': ('django.db.models.fields.CharField', [], {'default': "'f0b78a36a5b54af9b6712dace7a7eddd'", 'unique': 'True', 'max_length': '32'})
        },
        u'lizard_auth_server.organisationrole': {
            'Meta': {'unique_together': "((u'organisation', u'role'),)", 'object_name': 'OrganisationRole'},
            'for_all_users': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'organisation': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "u'organisation_roles'", 'to': u"orm['lizard_auth_server.Organisation']"}),
            'role': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "u'organisation_roles'", 'to': u"orm['lizard_auth_server.Role']"})
        },
        u'lizard_auth_server.portal': {
            'Meta': {'ordering': "(u'name',)", 'object_name': 'Portal'},
            'allowed_domain': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'redirect_url': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'sso_key': ('django.db.models.fields.CharField', [], {'default': "u'svxfPQ6ypln4p14Bj169mnYxro7eIosvOdcn5PiQLqTEYpdrEuV5l29aGTqToXoX'", 'unique': 'True', 'max_length': '64'}),
            'sso_secret': ('django.db.models.fields.CharField', [], {'default': "u'yvDPZjmZfaq5D3ip0ub6JEHPpkbEuoKsBKKSYkjTywSjPZ5MQzH7PBvJOuKLRkCf'", 'unique': 'True', 'max_length': '64'}),
            'visit_url': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        },
        u'lizard_auth_server.role': {
            'Meta': {'ordering': "[u'portal', u'name']", 'unique_together': "((u'name', u'portal'),)", 'object_name': 'Role'},
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'external_description': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'inheriting_roles': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'base_roles'", 'blank': 'True', 'to': u"orm['lizard_auth_server.Role']"}),
            'internal_description': ('django.db.models.fields.TextField', [], {'blank': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'portal': ('django.db.models.fields.related.ForeignKey', [], {'related_name': "u'roles'", 'to': u"orm['lizard_auth_server.Portal']"}),
            'unique_id': ('django.db.models.fields.CharField', [], {'default': "'d6a3b286385546ad9d5a76b2044e22dd'", 'unique': 'True', 'max_length': '32'})
        },
        u'lizard_auth_server.token': {
            'Meta': {'ordering': "(u'-created',)", 'object_name': 'Token'},
            'auth_token': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2015, 11, 12, 0, 0)'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'portal': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['lizard_auth_server.Portal']"}),
            'request_token': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': u"orm['auth.User']", 'null': 'True', 'blank': 'True'})
        },
        u'lizard_auth_server.userprofile': {
            'Meta': {'ordering': "[u'user__username']", 'object_name': 'UserProfile'},
            'created_at': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            u'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'mobile_phone_number': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'organisations': ('django.db.models.fields.related.ManyToManyField', [], {'blank': 'True', 'related_name': "u'user_profiles'", 'null': 'True', 'symmetrical': 'False', 'to': u"orm['lizard_auth_server.Organisation']"}),
            'phone_number': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'portals': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'related_name': "u'user_profiles'", 'blank': 'True', 'to': u"orm['lizard_auth_server.Portal']"}),
            'postal_code': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'roles': ('django.db.models.fields.related.ManyToManyField', [], {'blank': 'True', 'related_name': "u'user_profiles'", 'null': 'True', 'symmetrical': 'False', 'to': u"orm['lizard_auth_server.OrganisationRole']"}),
            'street': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'title': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'town': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'updated_at': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'related_name': "u'user_profile'", 'unique': 'True', 'to': u"orm['auth.User']"})
        }
    }

    complete_apps = ['lizard_auth_server']