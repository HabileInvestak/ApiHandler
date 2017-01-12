# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('restapp', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='user',
            old_name='public_key1',
            new_name='access_token',
        ),
        migrations.RenameField(
            model_name='user',
            old_name='public_key2',
            new_name='initial_token',
        ),
        migrations.RemoveField(
            model_name='user',
            name='public_key3',
        ),
        migrations.RemoveField(
            model_name='user',
            name='public_key4',
        ),
        migrations.RemoveField(
            model_name='user',
            name='user_session_id',
        ),
    ]
