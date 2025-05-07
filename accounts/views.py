from django.http import HttpResponse
from django.shortcuts import redirect, render

import jwt
from rest_framework import generics

from AuthRegisterDjango import settings
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
from django.contrib.auth.decorators import login_required


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
        
# HTML view for user registration
def register_page(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        raw_password = request.POST.get('password')

        hashed_pw = bcrypt.hashpw(raw_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        User.objects.create(username=username, email=email, password=hashed_pw)
        print("Welcome you have registerd succesfuly!")
        return redirect('login_page')

    return render(request, 'accounts/register.html')


# HTML view for login
def login_page(request):
    if request.method == 'POST':
        login_input = request.POST.get('username_or_email')
        password = request.POST.get('password')

        try:
            user = User.objects.get(Q(username=login_input) | Q(email=login_input))
        except User.DoesNotExist:
            return HttpResponse("Invalid username or email", status=401)

        if bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            refresh = RefreshToken.for_user(user)
            response = redirect('profile_page')
            response.set_cookie('access_token', str(refresh.access_token))  # Optional
            return response
        return HttpResponse("Incorrect password", status=401)

    return render(request, 'accounts/login.html')



def profile_page(request):
    token = request.COOKIES.get('access_token')  # Or get from header

    if not token:
        return redirect('login_page')  # or return a 403 page

    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user = User.objects.get(id=payload['user_id'])
    except (jwt.ExpiredSignatureError, jwt.DecodeError, User.DoesNotExist):
        return redirect('login_page')

    return render(request, 'accounts/profile.html', {'user': user})
