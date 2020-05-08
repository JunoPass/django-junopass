# Django JunoPass support

Implementation of [JunoPass Authentication](https://developers.junopass.com/junopass-api/authenticating-users) API for Django.

## Get access token and project id

Create an account for access token and project id - [JunoPass Console](https://console.junopass.com)


## Get JunoPass public key

Copy paste the JunoPass public key from ther [Documentation](https://developers.junopass.com/resources/junopass-public-key)


## Installation

    pip install djjunopass --upgrade


## Setup

Installed `djjunopass` in installed apps

    INSTALLED_APPS = [
        ..
        'djjunopass',
        ..
    ]

## Configuration

Update your setting files with the following:

    # Authentication
    LOGIN_URL = "djjunopass:login"

    # Set authentication to default JunoPass for Passwordless support
    AUTHENTICATION_BACKENDS = [
        "djjunopass.backends.JunoPassBackend",
    ]

    JUNOPASS_PUBLIC_KEY = <JUNOPASS-PUBLIC-KEY>

    JUNOPASS_PROJECT_ID = <JUNOPASS-PROJECT-ID>

    JUNOPASS_ACCESS_TOKEN = <JUNOPASS_ACCESS_TOKEN>

## Optional settings

    # Change default cookies settings
    JUNOPASS_DEVICE_PRIVATE_KEY_NAME = "JUNOPASS_DEVICE_PRIVATE_KEY"

    JUNOPASS_DEVICE_PUBLIC_KEY_NAME = "JUNOPASS_DEVICE_PUBLIC_KEY"
