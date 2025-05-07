from django.urls import path
from .views import LoginView, ProfileView, RegisterView, login_page, profile_page, register_page
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path('api/register/', RegisterView.as_view(), name='register'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/profile/', ProfileView.as_view(), name='profile'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # HTML views
    path('register/', register_page, name='register_page'),
    path('login/', login_page, name='login_page'),
    path('profile/', profile_page, name='profile_page'),
]
