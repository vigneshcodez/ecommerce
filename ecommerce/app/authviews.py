from django.contrib.auth import get_user_model
from django.conf import settings
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from .serializers import RegisterSerializer, EmailVerificationSerializer, LoginSerializer, UserSerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
import logging


User = get_user_model()

# @swagger_auto_schema(method='post', request_body=RegisterSerializer, responses={201: 'User registered. Check your email to verify your account.'})
# @api_view(['POST'])
# def register(request):
#     """
#     Register a new user.
#     """
#     serializer = RegisterSerializer(data=request.data)
#     if serializer.is_valid():
#         user = serializer.save()
#         token = RefreshToken.for_user(user).access_token
#         print(token)
#         send_mail(
#             'Verify your email',
#             f'Use this token to verify your email: {token}',
#             settings.DEFAULT_FROM_EMAIL,
#             [user.email],
#         )
#         return Response({'message': 'User registered. Check your email to verify your account.'}, status=status.HTTP_201_CREATED)
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='post', request_body=RegisterSerializer, responses={201: 'User registered. Check your email to verify your account.'})
@api_view(['POST'])
def register(request):
    """
    Register a new user.
    """
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        user.is_active = False
        user.save()

        # Generate a token for the new user
        token = RefreshToken.for_user(user).access_token
        verify_url = f"http://localhost:8000/verify-email/?token={token}"  # Include this in your email for ease
        send_mail(
            'Verify your email',
            f'Click the link to verify your email: {verify_url}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
        )
        return Response({'message': 'User registered. Check your email to verify your account.'}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='post', request_body=EmailVerificationSerializer, responses={200: 'Email verified successfully.'})
@api_view(['POST'])
def verify_email(request):
    """
    Verify user's email.
    """
    serializer = EmailVerificationSerializer(data=request.data)
    if serializer.is_valid():
        token = serializer.validated_data['token']
        try:
            # Decode the token without verifying the signature to get the user_id
            payload = UntypedToken(token).payload
            user_id = payload.get('user_id')
            if not user_id:
                raise TokenError('Invalid token payload')
            
            user = User.objects.get(id=user_id)
            user.is_active = True
            user.save()
            return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
        except (TokenError, InvalidToken, User.DoesNotExist) as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# @swagger_auto_schema(method='post', request_body=EmailVerificationSerializer, responses={200: 'Email verified successfully.'})
# @api_view(['POST'])
# def verify_email(request):
#     """
#     Verify user's email.
#     """
#     serializer = EmailVerificationSerializer(data=request.data)
#     if serializer.is_valid():
#         token = serializer.validated_data['token']
        
        
#         try:
#             user_id = RefreshToken(token).payload['user_id']
#             print(user_id)
        
#             user = User.objects.get(id=user_id)
#             user.is_active = True
#             user.save()
#             return Response({'message': 'Email verified successfully.'}, status=status.HTTP_200_OK)
#         except:
#             return Response({'error': 'Invalid token.'}, status=status.HTTP_400_BAD_REQUEST)
#     return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(method='post', request_body=LoginSerializer, responses={200: 'Login successful.'})
@api_view(['POST'])
def login(request):
    """
    Log in a user.
    """
    serializer = LoginSerializer(data=request.data)
    if serializer.is_valid():
        user = get_object_or_404(User, email=serializer.validated_data['email'])
        if user.check_password(serializer.validated_data['password']):
            if user.is_active:
                refresh = RefreshToken.for_user(user)
                return Response({'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)
            return Response({'error': 'Account is not active.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response({'error': 'Invalid credentials.'}, status=status.HTTP_400_BAD_REQUEST)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# @swagger_auto_schema(method='post', responses={200: 'Logged out successfully.'})
# @api_view(['POST'])
# def logout(request):
#     """
#     Log out a user.
#     """
#     request.auth.delete()
#     return Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)


# @swagger_auto_schema(method='post', responses={200: 'Logged out successfully.'})
# @api_view(['POST'])
# def logout(request):
#     """
#     Log out a user by blacklisting their refresh token.
#     """
#     try:
#         refresh_token = request.data["refresh_token"]
#         token = RefreshToken(refresh_token)
#         token.blacklist()
#         return Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)
#     except Exception as e:
#         return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

# Define the request body schema for logout
# logout_request_body = openapi.Schema(
#     type=openapi.TYPE_OBJECT,
#     properties={
#         'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token'),
#     },
#     required=['refresh_token']
# )

# @swagger_auto_schema(method='post', request_body=logout_request_body, responses={200: 'Logged out successfully.'})
# @api_view(['POST'])
# @permission_classes([IsAuthenticated])
# def logout(request):
#     """
#     Log out a user by blacklisting their refresh token.
#     """
#     refresh_token = request.data.get("refresh_token")
#     print(refresh_token)
#     if not refresh_token:
#         return Response({'error': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
    
#     try:
#         token = RefreshToken(refresh_token)
#         token.blacklist()
#         return Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)
#     except Exception as e:
#         return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

# Set up logger
logger = logging.getLogger(__name__)

# Define the request body schema for logout
logout_request_body = openapi.Schema(
    type=openapi.TYPE_OBJECT,
    properties={
        'refresh_token': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token'),
    },
    required=['refresh_token']
)

@swagger_auto_schema(method='post', request_body=logout_request_body, responses={200: 'Logged out successfully.'})
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    """
    Log out a user by blacklisting their refresh token.
    """
    logger.info("Logout request received.")
    refresh_token = request.data.get("refresh_token")
    if not refresh_token:
        return Response({'error': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        logger.info(f"Attempting to blacklist refresh token: {refresh_token}")
        token = RefreshToken(refresh_token)
        token.blacklist()
        return Response({'message': 'Logged out successfully.'}, status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    
# @swagger_auto_schema(method='delete', responses={204: 'User account deleted.'})
# @api_view(['DELETE'])
# @permission_classes([IsAuthenticated])
# def delete_user(request):
#     """
#     Delete the authenticated user's account.
#     """
#     user = request.user
#     # user.delete()
#     print(user)
#     return Response({'message': 'User account deleted.'}, status=status.HTTP_204_NO_CONTENT)

@swagger_auto_schema(method='delete', responses={204: 'User account deleted.'})
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_user(request):
    """
    Delete the authenticated user's account.
    """
    user = request.user
    user.delete()
    return Response({'message': 'User account deleted.'}, status=status.HTTP_204_NO_CONTENT)