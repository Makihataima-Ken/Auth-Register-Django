from django.shortcuts import render

from rest_framework import generics
from .serializers import RegisterSerializer
from rest_framework.permissions import AllowAny

from .serializers import LoginSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.contrib.auth import get_user_model
from django.db.models import Q
import bcrypt

from rest_framework.permissions import IsAuthenticated

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

User = get_user_model()

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        login_input = serializer.validated_data['username_or_email']
        password = serializer.validated_data['password']

        try:
            # Try to find the user by username OR email
            user = User.objects.get(Q(username=login_input) | Q(email=login_input))
        except User.DoesNotExist:
            return Response({'error': 'Account not found'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check password using bcrypt
        if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid password'}, status=status.HTTP_401_UNAUTHORIZED)
    
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]  # Require JWT toke
    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
        })