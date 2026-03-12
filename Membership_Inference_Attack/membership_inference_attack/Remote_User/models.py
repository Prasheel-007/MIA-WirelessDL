from django.db import models

# Create your models here.
from django.db.models import CASCADE


class ClientRegister_Model(models.Model):

    username = models.CharField(max_length=30)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=10)
    country = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    city = models.CharField(max_length=30)


class inference_attack_detection(models.Model):


    slno= models.CharField(max_length=3000)
    Flow_ID= models.CharField(max_length=3000)
    Source_IP= models.CharField(max_length=3000)
    Source_Port= models.CharField(max_length=3000)
    Destination_IP= models.CharField(max_length=3000)
    Destination_Port= models.CharField(max_length=3000)
    Protocol= models.CharField(max_length=3000)
    Timestamp= models.CharField(max_length=3000)
    Flow_Duration= models.CharField(max_length=3000)
    Total_Fwd_Packets= models.CharField(max_length=3000)
    Total_Length_of_Fwd_Packets= models.CharField(max_length=3000)
    Fwd_Packet_Length_Max= models.CharField(max_length=3000)
    Fwd_Packet_Length_Min= models.CharField(max_length=3000)
    Flow_Bytes_per_second= models.CharField(max_length=3000)
    Flow_Packets_per_second= models.CharField(max_length=3000)
    Fwd_Packets_per_second= models.CharField(max_length=3000)
    Min_Packet_Length= models.CharField(max_length=3000)
    Max_Packet_Length= models.CharField(max_length=3000)
    Packet_Length_ean= models.CharField(max_length=3000)
    ACK_Flag_Count= models.CharField(max_length=3000)
    Prediction= models.CharField(max_length=3000)

class detection_ratio(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)

class detection_accuracy(models.Model):

    names = models.CharField(max_length=300)
    ratio = models.CharField(max_length=300)


