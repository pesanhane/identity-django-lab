from django.contrib import admin

from django.urls import path,include

from users.authentication import (
    MFATokenObtainPairView,
    NormalTokenObtainPairView,
    MFARecoveryTokenObtainPairView,
    SessionTokenRefreshView,
)

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)



urlpatterns = [

    path("admin/",admin.site.urls),

    path( "api/users/",include("users.urls")),

    
    path("api/token/",NormalTokenObtainPairView.as_view(),name="token_obtain_pair"),
    path("api/token/mfa/",MFATokenObtainPairView.as_view(),name="token_mfa"),

    path("api/token/refresh/",SessionTokenRefreshView.as_view(),name="token_refresh",),
    path("api/token/mfa/recovery/",MFARecoveryTokenObtainPairView.as_view(),
    name="token_mfa_recovery",
),

]
