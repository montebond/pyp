import django
import smtplib
from django import forms
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.utils.translation import ugettext_lazy as _

class LoginUserForm(forms.ModelForm):

    """A form for creating new users.

    Includes all the required fields, plus a repeated password.

    """

    email = forms.EmailField(
        widget=forms.TextInput(
            attrs={
            'id':'inputWelcome',
            'class':'form-control email1',
            'placeholder':'Email Address',
            }
        )
    )

    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(
            attrs={
            'id':'inputWelcome',
            'class':'form-control password1',
            'placeholder':'Password',
            }
        )
    )

    class Meta:  # noqa: D101
        model = get_user_model()
        fields = ('email',)

class EmailUserCreationForm(forms.ModelForm):

    """A form for creating new users.

    Includes all the required fields, plus a repeated password.

    """

    error_messages = {
        'duplicate_email': _("A user with that email already exists."),
        'password_mismatch': _("The two password fields didn't match."),
    }

    email = forms.EmailField(
        widget=forms.TextInput(
            attrs={
            'id':'inputWelcome',
            'class':'form-control email2',
            'placeholder':'Email Address',
            }
        )
    )

    password1 = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(
            attrs={
            'id':'inputWelcome',
            'class':'form-control password2',
            'placeholder':'Password',
            }
        )
    )
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput(
            attrs={
            'id':'inputWelcome',
            'class':'form-control password3',
            'placeholder':'Re-Enter Password',
            }
        )
    )

    class Meta:  # noqa: D101
        model = get_user_model()
        fields = ('email',)

    def clean_email(self):
        email = self.cleaned_data["email"]
        try:
            get_user_model()._default_manager.get(email=email)
        except get_user_model().DoesNotExist:
            return email
        raise forms.ValidationError(
            self.error_messages['duplicate_email'],
            code='duplicate_email',
        )

    def clean_password2(self):
        """Check that the two password entries match.

        :return str password2: cleaned password2
        :raise forms.ValidationError: password2 != password1

        """
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError(
                self.error_messages['password_mismatch'],
                code='password_mismatch',
            )
        return password2

    def save(self, commit=True):
        """Save user.

        Save the provided password in hashed format.

        :return custom_user.models.EmailUser: user

        """
        user = super(EmailUserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
            email = self.cleaned_data["email"]
            subject = "Welcome to the uCloud"
            message = "Your journey on the uCloud is about to begin.."
            from_email = "noreply@ucloud.live"
            send_mail(subject, message, from_email, [email], fail_silently=False)
        return user

class ResetPasswordForm(forms.ModelForm):

    """A form for creating new users.

    Includes all the required fields, plus a repeated password.

    """

    error_messages = {
        'no_email': _("No user with that email exists"),
        'wrong_password': _("Incorrect password"),
    }

    email = forms.EmailField(
        widget=forms.TextInput(
            attrs={
            'id':'inputWelcome',
            'class':'form-control email2',
            'placeholder':'Email Address',
            }
        )
    )

    class Meta:  # noqa: D101
        model = get_user_model()
        fields = ('email',)

class EmailUserChangeForm(forms.ModelForm):

    """A form for updating users.

    Includes all the fields on the user, but replaces the password field
    with admin's password hash display field.

    """

    # In Django 1.9 the url for changing the password was changed (#15779)
    # A url name was also added in 1.9 (same issue #15779),
    # so reversing the url is not possible for Django < 1.9
    password = ReadOnlyPasswordHashField(label=_("Password"), help_text=_(
        "Raw passwords are not stored, so there is no way to see "
        "this user's password, but you can change the password "
        "using <a href=\"%(url)s\">this form</a>."
    ) % {'url': 'password/' if django.VERSION < (1, 9) else '../password/'})

    class Meta:  # noqa: D101
        model = get_user_model()
        exclude = ()

    def __init__(self, *args, **kwargs):
        """Init the form."""
        super(EmailUserChangeForm, self).__init__(*args, **kwargs)
        f = self.fields.get('user_permissions', None)
        if f is not None:
            f.queryset = f.queryset.select_related('content_type')

    def clean_password(self):
        """Clean password.

        Regardless of what the user provides, return the initial value.
        This is done here, rather than on the field, because the
        field does not have access to the initial value.

        :return str password:

        """
        return self.initial["password"]
