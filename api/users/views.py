from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            # Generate both access and refresh tokens
            refresh = RefreshToken.for_user(user)
            access = refresh.access_token

            # Prepare the response
            response = Response({
                'message': 'Login successful.',
                'username': user.username,
            }, status=status.HTTP_200_OK)

            # Set cookies with HttpOnly and secure flags
            response.set_cookie(
                key=str(api_settings.AUTH_COOKIE),
                value=str(access),
                expires=str(api_settings.ACCESS_TOKEN_LIFETIME),
                secure=bool(api_settings.AUTH_COOKIE_SECURE),
                httponly=bool(api_settings.AUTH_COOKIE_HTTP_ONLY),
                samesite=str(api_settings.AUTH_COOKIE_SAMESITE)
            )
            response.set_cookie(
                key=str(api_settings.AUTH_COOKIE_REFRESH),
                value=str(refresh),
                expires=str(api_settings.REFRESH_TOKEN_LIFETIME),
                secure=bool(api_settings.AUTH_COOKIE_SECURE),
                httponly=bool(api_settings.AUTH_COOKIE_HTTP_ONLY),
                samesite=str(api_settings.AUTH_COOKIE_SAMESITE)
            )

            return response
        else:
            return Response({
                'error': 'Invalid credentials.'
            }, status=status.HTTP_400_BAD_REQUEST)


class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.COOKIES.get(api_settings.AUTH_COOKIE_REFRESH)

        if not refresh_token:
            raise AuthenticationFailed('Refresh token is missing.')

        try:
            # Use Simple JWT's built-in serializer to validate the refresh token
            serializer = TokenRefreshSerializer(data={'refresh': refresh_token})
            serializer.is_valid(raise_exception=True)
            new_access_token = serializer.validated_data['access']

            # Prepare the response and set the new access token cookie
            response = Response({'message': 'Access token refreshed.'}, status=status.HTTP_200_OK)
            response.set_cookie(
                key=str(api_settings.AUTH_COOKIE),
                value=str(new_access_token),
                expires=str(api_settings.ACCESS_TOKEN_LIFETIME),
                secure=bool(api_settings.AUTH_COOKIE_SECURE),
                httponly=bool(api_settings.AUTH_COOKIE_HTTP_ONLY),
                samesite=str(api_settings.AUTH_COOKIE_SAMESITE)
            )
            return response

        except Exception as e:
            raise AuthenticationFailed('Refresh token is invalid or expired.')
