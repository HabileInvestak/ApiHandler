# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('restapp', '0007_auto_20170110_2134'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='access_token',
            field=models.CharField(max_length=200000000000000000000000L),
        ),
        migrations.AlterField(
            model_name='user',
            name='initial_token',
            field=models.CharField(max_length=20000000000000000000000L),
        ),
    ]
