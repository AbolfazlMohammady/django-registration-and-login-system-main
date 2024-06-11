from django.urls import path
from .views import home, profile, RegisterView
from . import views

urlpatterns = [
    path('', home, name='users-home'),
    path('register/', RegisterView.as_view(), name='users-register'),
    path('profile/', profile, name='users-profile'),

    # path('des-encrypt/', views.des_encrypt_view, name='des_encrypt'),
    # path('des-decrypt/', views.des_decrypt_view, name='des_decrypt'),
    # path('aes-encrypt/', views.aes_encrypt_view, name='aes_encrypt'),
    # path('aes-decrypt/', views.aes_decrypt_view, name='aes_decrypt'),
    # path('rsa-encrypt/', views.rsa_encrypt_view, name='rsa_encrypt'),
    # path('rsa-decrypt/', views.rsa_decrypt_view, name='rsa_decrypt'),
    # path('elgamal-encrypt/', views.elgamal_encrypt_view, name='elgamal_encrypt'),
    # path('elgamal-decrypt/', views.elgamal_decrypt_view, name='elgamal_decrypt'),
    # path('hash-md5/', views.hash_md5_view, name='hash_md5'),
    # path('hash-sha1/', views.hash_sha1_view, name='hash_sha1'),
    # path('hash-sha256/', views.hash_sha256_view, name='hash_sha256'),
    # path('hmac/', views.hmac_view, name='hmac'),
]
