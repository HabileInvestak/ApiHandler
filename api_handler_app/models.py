from django.db import models

# Create your models here.

class User(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    user_id = models.TextField(primary_key=True,unique=True,null=False)
    initial_token = models.TextField()
    access_token = models.TextField()

    class Meta:
        ordering = ('created',)

class Audit(models.Model):
    investak_request_time_stamp = models.DateTimeField(null=True)
    api_request_time_stamp = models.DateTimeField(null=True)
    tso_response_time_stamp = models.DateTimeField(null=True)
    api_response_time_stamp = models.DateTimeField (null=True)
    user_id = models.TextField()
    request_id = models.AutoField(primary_key=True,unique=True,null=False)
    investak_request = models.TextField()
    api_request = models.TextField()
    tso_response = models.TextField()
    api_response = models.TextField()
    api_status = models.TextField()
    tso_status = models.TextField()


    class Meta:
        ordering = ('request_id',)