from django.db import models

# Create your models here.

class User(models.Model):
    created = models.DateTimeField(auto_now_add=True)
    user_id = models.TextField()
    public_key1 = models.TextField()
    public_key2 = models.TextField()
    public_key1 = models.TextField()
    public_key3 = models.TextField()
    public_key4 = models.TextField()
    user_session_id= models.TextField()

    class Meta:
        ordering = ('created',)