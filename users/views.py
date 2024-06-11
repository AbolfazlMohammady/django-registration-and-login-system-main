from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordChangeView
from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin
from django.views import View
from django.contrib.auth.decorators import login_required

from .forms import RegisterForm, LoginForm, UpdateUserForm, UpdateProfileForm


def home(request):
    return render(request, 'users/home.html')


class RegisterView(View):
    form_class = RegisterForm
    initial = {'key': 'value'}
    template_name = 'users/register.html'

    def dispatch(self, request, *args, **kwargs):
        # will redirect to the home page if a user tries to access the register page while logged in
        if request.user.is_authenticated:
            return redirect(to='/')

        # else process dispatch as it otherwise normally would
        return super(RegisterView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        form = self.form_class(request.POST)

        if form.is_valid():
            form.save()

            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}')

            return redirect(to='login')

        return render(request, self.template_name, {'form': form})


# Class based view that extends from the built in login view to add a remember me functionality
class CustomLoginView(LoginView):
    form_class = LoginForm

    def form_valid(self, form):
        remember_me = form.cleaned_data.get('remember_me')

        if not remember_me:
            # set session expiry to 0 seconds. So it will automatically close the session after the browser is closed.
            self.request.session.set_expiry(0)

            # Set session as modified to force data updates/cookie to be saved.
            self.request.session.modified = True

        # else browser session will be as long as the session cookie time "SESSION_COOKIE_AGE" defined in settings.py
        return super(CustomLoginView, self).form_valid(form)


class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email.html'
    subject_template_name = 'users/password_reset_subject'
    success_message = "We've emailed you instructions for setting your password, " \
                      "if an account exists with the email you entered. You should receive them shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the address you registered with, and check your spam folder."
    success_url = reverse_lazy('users-home')


class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'users/change_password.html'
    success_message = "Successfully Changed Your Password"
    success_url = reverse_lazy('users-home')


@login_required
def profile(request):
    if request.method == 'POST':
        user_form = UpdateUserForm(request.POST, instance=request.user)
        profile_form = UpdateProfileForm(request.POST, request.FILES, instance=request.user.profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile is updated successfully')
            return redirect(to='users-profile')
    else:
        user_form = UpdateUserForm(instance=request.user)
        profile_form = UpdateProfileForm(instance=request.user.profile)

    return render(request, 'users/profile.html', {'user_form': user_form, 'profile_form': profile_form})
# myapp/views.py
# from django.shortcuts import render
# from django.http import JsonResponse
# from .crypto_utils import des_encrypt, des_decrypt, aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, elgamal_encrypt, elgamal_decrypt, generate_md5, generate_sha1, generate_sha256, generate_hmac
# from .forms import EncryptionForm, DecryptionForm, HashForm, HmacForm

# def home(request):
#     return render(request, 'home.html')

# def des_encrypt_view(request):
#     if request.method == 'POST':
#         form = EncryptionForm(request.POST)
#         if form.is_valid():
#             data = form.cleaned_data['data'].encode()
#             key = form.cleaned_data['key'].encode()
#             encrypted_data = des_encrypt(data, key)
#             return render(request, 'result.html', {'result': encrypted_data.hex()})
#     else:
#         form = EncryptionForm()
#     return render(request, 'des_encrypt.html', {'form': form})

# def des_decrypt_view(request):
#     if request.method == 'POST':
#         form = DecryptionForm(request.POST)
#         if form.is_valid():
#             data = bytes.fromhex(form.cleaned_data['data'])
#             key = form.cleaned_data['key'].encode()
#             decrypted_data = des_decrypt(data, key)
#             return render(request, 'result.html', {'result': decrypted_data.decode()})
#     else:
#         form = DecryptionForm()
#     return render(request, 'des_decrypt.html', {'form': form})

# def aes_encrypt_view(request):
#     if request.method == 'POST':
#         form = EncryptionForm(request.POST)
#         if form.is_valid():
#             data = form.cleaned_data['data'].encode()
#             key = form.cleaned_data['key'].encode()
#             encrypted_data = aes_encrypt(data, key)
#             return render(request, 'result.html', {'result': encrypted_data.hex()})
#     else:
#         form = EncryptionForm()
#     return render(request, 'aes_encrypt.html', {'form': form})

# def aes_decrypt_view(request):
#     if request.method == 'POST':
#         form = DecryptionForm(request.POST)
#         if form.is_valid():
#             data = bytes.fromhex(form.cleaned_data['data'])
#             key = form.cleaned_data['key'].encode()
#             decrypted_data = aes_decrypt(data, key)
#             return render(request, 'result.html', {'result': decrypted_data.decode()})
#     else:
#         form = DecryptionForm()
#     return render(request, 'aes_decrypt.html', {'form': form})

# def rsa_encrypt_view(request):
#     if request.method == 'POST':
#         form = EncryptionForm(request.POST)
#         if form.is_valid():
#             data = form.cleaned_data['data'].encode()
#             public_key = RSA.import_key(form.cleaned_data['key'])
#             encrypted_data = rsa_encrypt(data, public_key)
#             return render(request, 'result.html', {'result': encrypted_data.hex()})
#     else:
#         form = EncryptionForm()
#     return render(request, 'rsa_encrypt.html', {'form': form})

# def rsa_decrypt_view(request):
#     if request.method == 'POST':
#         form = DecryptionForm(request.POST)
#         if form.is_valid():
#             data = bytes.fromhex(form.cleaned_data['data'])
#             private_key = RSA.import_key(form.cleaned_data['key'])
#             decrypted_data = rsa_decrypt(data, private_key)
#             return render(request, 'result.html', {'result': decrypted_data.decode()})
#     else:
#         form = DecryptionForm()
#     return render(request, 'rsa_decrypt.html', {'form': form})

# def elgamal_encrypt_view(request):
#     if request.method == 'POST':
#         form = EncryptionForm(request.POST)
#         if form.is_valid():
#             data = form.cleaned_data['data'].encode()
#             public_key = ElGamal.import_key(form.cleaned_data['key'])
#             encrypted_data = elgamal_encrypt(data, public_key)
#             return render(request, 'result.html', {'result': encrypted_data.hex()})
#     else:
#         form = EncryptionForm()
#     return render(request, 'elgamal_encrypt.html', {'form': form})

# def elgamal_decrypt_view(request):
#     if request.method == 'POST':
#         form = DecryptionForm(request.POST)
#         if form.is_valid():
#             data = bytes.fromhex(form.cleaned_data['data'])
#             private_key = ElGamal.import_key(form.cleaned_data['key'])
#             decrypted_data = elgamal_decrypt(data, private_key)
#             return render(request, 'result.html', {'result': decrypted_data.decode()})
#     else:
#         form = DecryptionForm()
#     return render(request, 'elgamal_decrypt.html', {'form': form})

# def hash_md5_view(request):
#     if request.method == 'POST':
#         form = HashForm(request.POST)
#         if form.is_valid():
#             data = form.cleaned_data['data'].encode()
#             hashed_data = generate_md5(data)
#             return render(request, 'result.html', {'result': hashed_data})
#     else:
#         form = HashForm()
#     return render(request, 'hash_md5.html', {'form': form})

# def hash_sha1_view(request):
#     if request.method == 'POST':
#         form = HashForm(request.POST)
#         if form.is_valid():
#             data = form.cleaned_data['data'].encode()
#             hashed_data = generate_sha1(data)
#             return render(request, 'result.html', {'result': hashed_data})
#     else:
#         form = HashForm()
#     return render(request, 'hash_sha1.html', {'form': form})

# def hash_sha256_view(request):
#     if request.method == 'POST':
#         form = HashForm(request.POST)
#         if form.is_valid():
#             data = form.cleaned_data['data'].encode()
#             hashed_data = generate_sha256(data)
#             return render(request, 'result.html', {'result': hashed_data})
#     else:
#         form = HashForm()
#     return render(request, 'hash_sha256.html', {'form': form})

# def hmac_view(request):
#     if request.method == 'POST':
#         form = HmacForm(request.POST)
#         if form.is_valid():
#             key = form.cleaned_data['key'].encode()
#             data = form.cleaned_data['data'].encode()
#             hmac_data = generate_hmac(key, data)
#             return render(request, 'result.html', {'result': hmac_data})
#     else:
#         form = HmacForm()
#     return render(request, 'hmac.html', {'form': form})
