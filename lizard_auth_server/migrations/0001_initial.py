# -*- coding: utf-8 -*-
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models


class Migration(SchemaMigration):

    def forwards(self, orm):
        # Adding model 'Portal'
        db.create_table('lizard_auth_server_portal', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('sso_secret', self.gf('django.db.models.fields.CharField')(default=u'roscxyC81aB6cik80EF6CJhNbJjBbiCgfufJG7s3S352MyMoZKd4Q8wMUOK4T8Q2', unique=True, max_length=64)),
            ('sso_key', self.gf('django.db.models.fields.CharField')(default=u'tDO4bTYH6ppfBLLkRpiuiPshLrWLBkFpEueKuQsdq6bpB3OSfsMM9CV3OVNT6Gj7', unique=True, max_length=64)),
            ('redirect_url', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('visit_url', self.gf('django.db.models.fields.CharField')(max_length=255)),
        ))
        db.send_create_signal('lizard_auth_server', ['Portal'])

        # Adding model 'Token'
        db.create_table('lizard_auth_server_token', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('portal', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['lizard_auth_server.Portal'])),
            ('request_token', self.gf('django.db.models.fields.CharField')(unique=True, max_length=64)),
            ('auth_token', self.gf('django.db.models.fields.CharField')(unique=True, max_length=64)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True)),
            ('created', self.gf('django.db.models.fields.DateTimeField')(default=datetime.datetime(2012, 12, 18, 0, 0))),
        ))
        db.send_create_signal('lizard_auth_server', ['Token'])

        # Adding model 'UserProfile'
        db.create_table('lizard_auth_server_userprofile', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.OneToOneField')(to=orm['auth.User'], unique=True)),
            ('created_at', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('updated_at', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('organisation', self.gf('django.db.models.fields.CharField')(default=u'', max_length=255, null=True, blank=True)),
            ('title', self.gf('django.db.models.fields.CharField')(default=u'', max_length=255, null=True, blank=True)),
            ('street', self.gf('django.db.models.fields.CharField')(default=u'', max_length=255, null=True, blank=True)),
            ('postal_code', self.gf('django.db.models.fields.CharField')(default=u'', max_length=255, null=True, blank=True)),
            ('town', self.gf('django.db.models.fields.CharField')(default=u'', max_length=255, null=True, blank=True)),
            ('phone_number', self.gf('django.db.models.fields.CharField')(default=u'', max_length=255, null=True, blank=True)),
            ('mobile_phone_number', self.gf('django.db.models.fields.CharField')(default=u'', max_length=255, null=True, blank=True)),
        ))
        db.send_create_signal('lizard_auth_server', ['UserProfile'])

        # Adding M2M table for field portals on 'UserProfile'
        db.create_table('lizard_auth_server_userprofile_portals', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('userprofile', models.ForeignKey(orm['lizard_auth_server.userprofile'], null=False)),
            ('portal', models.ForeignKey(orm['lizard_auth_server.portal'], null=False))
        ))
        db.create_unique('lizard_auth_server_userprofile_portals', ['userprofile_id', 'portal_id'])

        # Adding model 'Invitation'
        db.create_table('lizard_auth_server_invitation', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('name', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('email', self.gf('django.db.models.fields.EmailField')(max_length=75)),
            ('organisation', self.gf('django.db.models.fields.CharField')(max_length=255)),
            ('language', self.gf('django.db.models.fields.CharField')(max_length=16)),
            ('created_at', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('activation_key', self.gf('django.db.models.fields.CharField')(max_length=64, unique=True, null=True, blank=True)),
            ('activation_key_date', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('is_activated', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('activated_on', self.gf('django.db.models.fields.DateTimeField')(null=True, blank=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'], null=True, blank=True)),
        ))
        db.send_create_signal('lizard_auth_server', ['Invitation'])

        # Adding M2M table for field portals on 'Invitation'
        db.create_table('lizard_auth_server_invitation_portals', (
            ('id', models.AutoField(verbose_name='ID', primary_key=True, auto_created=True)),
            ('invitation', models.ForeignKey(orm['lizard_auth_server.invitation'], null=False)),
            ('portal', models.ForeignKey(orm['lizard_auth_server.portal'], null=False))
        ))
        db.create_unique('lizard_auth_server_invitation_portals', ['invitation_id', 'portal_id'])


    def backwards(self, orm):
        # Deleting model 'Portal'
        db.delete_table('lizard_auth_server_portal')

        # Deleting model 'Token'
        db.delete_table('lizard_auth_server_token')

        # Deleting model 'UserProfile'
        db.delete_table('lizard_auth_server_userprofile')

        # Removing M2M table for field portals on 'UserProfile'
        db.delete_table('lizard_auth_server_userprofile_portals')

        # Deleting model 'Invitation'
        db.delete_table('lizard_auth_server_invitation')

        # Removing M2M table for field portals on 'Invitation'
        db.delete_table('lizard_auth_server_invitation_portals')


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
        'lizard_auth_server.portal': {
            'Meta': {'object_name': 'Portal'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'redirect_url': ('django.db.models.fields.CharField', [], {'max_length': '255'}),
            'sso_key': ('django.db.models.fields.CharField', [], {'default': "u'E987gc9EI1LXf9JksJowYTVK2Bp8MAXdbPYYXSzZ4JG3XIevJBiwBoCo9FM5TcNQ'", 'unique': 'True', 'max_length': '64'}),
            'sso_secret': ('django.db.models.fields.CharField', [], {'default': "u'P2UwPvfKuUJoi2T14Y3ajChL5q4dW2DplMa3rcIJBEM6MYilUjSRWeTSB4kg50rv'", 'unique': 'True', 'max_length': '64'}),
            'visit_url': ('django.db.models.fields.CharField', [], {'max_length': '255'})
        },
        'lizard_auth_server.token': {
            'Meta': {'object_name': 'Token'},
            'auth_token': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '64'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime(2012, 12, 18, 0, 0)'}),
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
            'phone_number': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'portals': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['lizard_auth_server.Portal']", 'symmetrical': 'False', 'blank': 'True'}),
            'postal_code': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'street': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'title': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'town': ('django.db.models.fields.CharField', [], {'default': "u''", 'max_length': '255', 'null': 'True', 'blank': 'True'}),
            'updated_at': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'user': ('django.db.models.fields.related.OneToOneField', [], {'to': "orm['auth.User']", 'unique': 'True'})
        }
    }

    complete_apps = ['lizard_auth_server']