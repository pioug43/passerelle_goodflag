from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('base', '0035_update_trace_email'),
    ]

    operations = [
        migrations.CreateModel(
            name='GoodflagResource',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=50, verbose_name='Title')),
                ('slug', models.SlugField(unique=True, verbose_name='Identifier')),
                ('description', models.TextField(verbose_name='Description')),
                ('base_url', models.URLField(
                    help_text='Ex: https://sgs-demo-test01.sunnystamp.com/api',
                    max_length=512,
                    verbose_name="URL de base de l'API Goodflag",
                )),
                ('access_token', models.CharField(
                    help_text='Bearer token (format: act_xxx.yyy)',
                    max_length=512,
                    verbose_name="Token d'accès API",
                )),
                ('user_id', models.CharField(
                    help_text='Utilisateur Goodflag propriétaire des workflows (format: usr_xxx)',
                    max_length=256,
                    verbose_name='Identifiant utilisateur API',
                )),
                ('timeout', models.PositiveIntegerField(default=30, verbose_name='Timeout HTTP (secondes)')),
                ('verify_ssl', models.BooleanField(default=True, verbose_name='Vérifier le certificat SSL')),
                ('default_consent_page_id', models.CharField(
                    blank=True, default='', help_text='Format: cop_xxx',
                    max_length=256, verbose_name='ID de page de consentement par défaut',
                )),
                ('default_signature_profile_id', models.CharField(
                    blank=True, default='', help_text='Format: sip_xxx',
                    max_length=256, verbose_name='ID de profil de signature par défaut',
                )),
                ('default_layout_id', models.CharField(
                    blank=True, default='',
                    help_text='Format: lay_xxx, requis si vous utilisez des métadonnées',
                    max_length=256, verbose_name='ID de layout par défaut',
                )),
                ('users', models.ManyToManyField(
                    blank=True, related_name='+', related_query_name='+', to='base.apiuser',
                )),
            ],
            options={
                'verbose_name': 'Connecteur Goodflag (signature électronique)',
                'verbose_name_plural': 'Connecteurs Goodflag (signature électronique)',
            },
        ),
    ]
