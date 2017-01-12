from django.db import models

# Create your models here.



class User(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    user_id = models.TextField(primary_key=True,unique=True,null=False)
    initial_token = models.TextField()
    access_token = models.TextField()

    class Meta:
        ordering = ('created',)