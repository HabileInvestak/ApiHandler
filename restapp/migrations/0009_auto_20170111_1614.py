# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('restapp', '0008_auto_20170110_2138'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='access_token',
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name='user',
            name='initial_token',
            field=models.TextField(),
        ),
    ]
