# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Audit',
            fields=[
                ('request_Time_Stamp', models.DateTimeField(auto_now_add=True)),
                ('response_Time_Stamp', models.DateTimeField(auto_now_add=True)),
                ('user_id', models.TextField()),
                ('request_id', models.AutoField(unique=True, serialize=False, primary_key=True)),
                ('request', models.TextField()),
                ('response', models.TextField()),
                ('status', models.TextField()),
            ],
            options={
                'ordering': ('request_id',),
            },
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('created', models.DateTimeField(auto_now_add=True)),
                ('user_id', models.TextField(unique=True, serialize=False, primary_key=True)),
                ('initial_token', models.TextField()),
                ('access_token', models.TextField()),
            ],
            options={
                'ordering': ('created',),
            },
        ),
    ]
