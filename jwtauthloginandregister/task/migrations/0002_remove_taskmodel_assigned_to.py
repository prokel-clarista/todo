# Generated by Django 4.1.5 on 2023-02-02 07:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('task', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='taskmodel',
            name='assigned_to',
        ),
    ]
