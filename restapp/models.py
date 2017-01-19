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
    request_Time_Stamp = models.DateTimeField(auto_now_add=True)
    response_Time_Stamp = models.DateTimeField(auto_now_add=True)
    user_id = models.TextField()
    request_id = models.AutoField(primary_key=True,unique=True,null=False)
    request = models.TextField()
    response = models.TextField()
    status = models.TextField()


    class Meta:
        ordering = ('request_id',)