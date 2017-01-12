# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('restapp', '0006_auto_20170110_2007'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='access_token',
            field=models.CharField(max_length=16384),
        ),
        migrations.AlterField(
            model_name='user',
            name='initial_token',
            field=models.CharField(max_length=16384),
        ),
    ]
