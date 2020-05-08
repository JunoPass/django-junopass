from django import forms


class AuthForm(forms.Form):
    identifier = forms.EmailField(label="Email address", widget=forms.TextInput(
        attrs={'placeholder': 'e.g name@company.com'}))


class VerifyForm(forms.Form):
    otp = forms.IntegerField(label="Verification Code")
