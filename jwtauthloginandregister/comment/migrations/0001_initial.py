# Generated by Django 4.1.5 on 2023-02-02 07:49

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='CommentModel',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False)),
                ('description', models.TextField()),
                ('created_by_name', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now_add=True)),
                ('up_votes', models.IntegerField(default=0)),
                ('total_comments', models.IntegerField(default=0)),
                ('created_by_id', models.IntegerField()),
                ('task_id', models.IntegerField()),
            ],
        ),
    ]