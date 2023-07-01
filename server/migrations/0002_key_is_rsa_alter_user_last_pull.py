# Generated by Django 4.2.2 on 2023-07-01 09:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('server', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='key',
            name='is_rsa',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='last_pull',
            field=models.DateTimeField(auto_now=True),
        ),
    ]