# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('user_id', models.TextField()),
                ('public_key2', models.TextField()),
                ('public_key1', models.TextField()),
                ('public_key3', models.TextField()),
                ('public_key4', models.TextField()),
                ('user_session_id', models.TextField()),
            ],
            options={
                'ordering': ('created',),
            },
        ),
    ]
