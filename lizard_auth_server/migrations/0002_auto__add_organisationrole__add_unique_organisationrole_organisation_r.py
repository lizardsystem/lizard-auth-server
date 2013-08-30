# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'OrganisationRole'
        db.create_table('lizard_auth_server_organisationrole', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('organisation', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['lizard_auth_server.Organisation'])),
            ('role', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['lizard_auth_server.Role'])),
            ('for_all_users', self.gf('django.db.models.fields.BooleanField')(default=False)),
        ))
        db.send_create_signal('lizard_auth_server', ['OrganisationRole'])

        # Adding unique constraint on 'OrganisationRole', fields ['organisation', 'role']
        db.create_unique('lizard_auth_server_organisationrole', ['organisation_id', 'role_id'])

        # Adding model 'Role'
        db.create_table('lizard_auth_server_role', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('unique_id', self.gf('django.db.models.fields.CharField')(default='9bd158a125324cf7a93003236b3e8403', unique=True, max_length=32)),
            ('code', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('external_description', self.gf('django.db.models.fields.TextField')()),
            ('internal_description', self.gf('django.db.models.fields.TextField')()),
            ('portal', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['lizard_auth_server.Portal'])),
        ))
        db.send_create_signal('lizard_auth_server', ['Role'])

        # Adding unique constraint on 'Role', fields ['name', 'portal']
        db.create_unique('lizard_auth_server_role', ['name', 'portal_id'])

        # Adding model 'Organisation'
        db.create_table('lizard_auth_server_organisation', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(unique=True, max_length=255)),
            ('unique_id', self.gf('django.db.models.fields.CharField')(default='90ebb418a2084824a34edffcbe6994fe', unique=True, max_length=32)),
        ))
        db.send_create_signal('lizard_auth_server', ['Organisation'])

        # Adding M2M table for field organisations on 'UserProfile'
        db.create_table('lizard_auth_server_userprofile_organisations', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('userprofile', models.ForeignKey(orm['lizard_auth_server.userprofile'], null=False)),
            ('organisation', models.ForeignKey(orm['lizard_auth_server.organisation'], null=False))
        ))
        db.create_unique('lizard_auth_server_userprofile_organisations', ['userprofile_id', 'organisation_id'])

        # Adding M2M table for field roles on 'UserProfile'
        db.create_table('lizard_auth_server_userprofile_roles', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('userprofile', models.ForeignKey(orm['lizard_auth_server.userprofile'], null=False)),
            ('organisationrole', models.ForeignKey(orm['lizard_auth_server.organisationrole'], null=False))
        ))
        db.create_unique('lizard_auth_server_userprofile_roles', ['userprofile_id', 'organisationrole_id'])


    def backwards(self, orm):
        # Removing unique constraint on 'Role', fields ['name', 'portal']
        db.delete_unique('lizard_auth_server_role', ['name', 'portal_id'])

        # Removing unique constraint on 'OrganisationRole', fields ['organisation', 'role']
        db.delete_unique('lizard_auth_server_organisationrole', ['organisation_id', 'role_id'])

        # Deleting model 'OrganisationRole'
        db.delete_table('lizard_auth_server_organisationrole')

        # Deleting model 'Role'
        db.delete_table('lizard_auth_server_role')

        # Deleting model 'Organisation'
        db.delete_table('lizard_auth_server_organisation')

        # Removing M2M table for field organisations on 'UserProfile'
        db.delete_table('lizard_auth_server_userprofile_organisations')

        # Removing M2M table for field roles on 'UserProfile'
        db.delete_table('lizard_auth_server_userprofile_roles')


    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        'auth.permission': {
            'Meta': {'ordering': "('content_type__app_label', 'content_type__model', 'codename')", 'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'lizard_auth_server.invitation': {
            'Meta': {'object_name': 'Invitation'},
            'activated_on': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'activation_key': ('django.db.models.fields.CharField', [], {'max_length': '64', 'unique': 'True', 'null': 'True', 'blank': 'True'}),
            'activation_key_date': ('django.db.models.fields.DateTimeField', [], {'null': 'True', 'blank': 'True'}),
            'created_at': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_activated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'language': ('django.db.models.fields.CharField', [], {'max_length': '16'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'organisation': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'portals': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['lizard_auth_server.Portal']", 'symmetrical': 'False', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']", 'null': 'True', 'blank': 'True'})
        },
        'lizard_auth_server.organisation': {
            'Meta': {'object_name': 'Organisation'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '255'}),
            'roles': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['lizard_auth_server.Role']", 'symmetrical': 'False', 'through': "orm['lizard_auth_server.OrganisationRole']", 'blank': 'True'}),
            'unique_id': ('django.db.models.fields.CharField', [], {'default': "'06deeb998f4f4268811ff56fbb5f5988'", 'unique': 'True', 'max_length': '32'})
        },
        'lizard_auth_server.organisationrole': {
            'Meta': {'unique_together': "((u'organisation', u'role'),)", 'object_name': 'OrganisationRole'},
            'for_all_users': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'organisation': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['lizard_auth_server.Organisation']"}),
            'role': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['lizard_auth_server.Role']"})
        },
        'lizard_auth_server.portal': {
            'Meta': {'ordering': "(u'name',)", 'object_name': 'Portal'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'redirect_url': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'sso_key': ('django.db.models.fields.CharField', [], {'default': "u'ChhGcWWJqY2uKN6GH4gRGia6eJG5q7M7kt2v3aKcnPhzBJL1LPvj9IYsElGA5QWL'", 'unique': 'True', 'max_length': '64'}),
            'sso_secret': ('django.db.models.fields.CharField', [], {'default': "u'NHWb3saBnCBfWVx1ygUAFKNtdrhGsfuXdWKjVwHwSEDxEnEgmZwYFj0T2A5LzFie'", 'unique': 'True', 'max_length': '64'}),
            'visit_url': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        },
        'lizard_auth_server.role': {
            'Meta': {'unique_together': "((u'name', u'portal'),)", 'object_name': 'Role'},
            'code': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'external_description': ('django.db.models.fields.TextField', [], {}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'internal_description': ('django.db.models.fields.TextField', [], {}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'portal': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['lizard_auth_server.Portal']"}),
            'unique_id': ('django.db.models.fields.CharField', [], {'default': "'71923e6e629840929e3894d5e7fee9dd'", 'unique': 'True', 'max_length': '32'})
        },
        'lizard_auth_server.token': {
            'Meta': {'object_name': 'Token'},
            'auth_token': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2013, 8, 29, 0, 0)'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'portal': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['lizard_auth_server.Portal']"}),
            'request_token': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']", 'null': 'True'})
        },
        'lizard_auth_server.userprofile': {
            'Meta': {'object_name': 'UserProfile'},
            'created_at': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'mobile_phone_number': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'organisation': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'organisations': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': "orm['lizard_auth_server.Organisation']", 'null': 'True', 'blank': 'True'}),
            'phone_number': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'portals': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['lizard_auth_server.Portal']", 'symmetrical': 'False', 'blank': 'True'}),
            'postal_code': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'roles': ('django.db.models.fields.related.ManyToManyField', [], {'symmetrical': 'False', 'to': "orm['lizard_auth_server.OrganisationRole']", 'null': 'True', 'blank': 'True'}),
            'street': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'title': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'town': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'updated_at': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'to': "orm['auth.User']", 'unique': 'True'})
        }
    }

    complete_apps = ['lizard_auth_server']