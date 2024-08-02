from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.request import Request
from rest_framework import status
from rest_framework.response import Response
from .models import Slider
from .serializers import SliderSerializer


# Create your views here.



@api_view(['GET'])
def slider(request=Request):
    sliders = Slider.objects.all()
    serializer = SliderSerializer(sliders,many=True)
    response = {
        "message":"sliders got succesfully",
        "data":serializer.data
    }
    return Response(response,status=status.HTTP_200_OK)


    
