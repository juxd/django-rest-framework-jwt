# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import datetime

import jwt

from django.contrib.auth import authenticate, get_user_model
from django.utils.translation import ugettext as _

from rest_framework import serializers

from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.utils import unix_epoch, get_username_field


def _check_payload(token):
    try:
        payload = JSONWebTokenAuthentication.jwt_decode_token(token)
    except jwt.ExpiredSignature:
        msg = _('Token has expired.')
        raise serializers.ValidationError(msg)
    except jwt.DecodeError:
        msg = _('Error decoding token.')
        raise serializers.ValidationError(msg)

    return payload


def _check_user(payload):
    username = JSONWebTokenAuthentication. \
        jwt_get_username_from_payload(payload)

    if not username:
        msg = _('Invalid token.')
        raise serializers.ValidationError(msg)

    # Make sure user exists
    try:
        User = get_user_model()
        user = User.objects.get_by_natural_key(username)
    except User.DoesNotExist:
        msg = _("User doesn't exist.")
        raise serializers.ValidationError(msg)

    if not user.is_active:
        msg = _('User account is disabled.')
        raise serializers.ValidationError(msg)

    return user


def _get_credentials(data):
    return {
        self.username_field: data.get(self.username_field),
        'password': data.get('password')
    }


class BaseJSONWebTokenSerializer(serializers.Serializer):
    """
    Serionalizer class used to validate anything.
    """

    token = serializers.CharField(read_only=True)

    def __init__(self, *args, **kwargs):
        """Dynamically add custom fields."""
        custom_auth = kwargs.pop('custom_auth', authenticate)
        extract_credential = kwargs.pop('extract_credential', _get_credentials)
        super().__init__(*args, **kwargs)

        for field, field_props in kwargs.get('fields', []):
            self.fields[field] = serializers.CharField(write_only=True,
                                                      required=True,
                                                      **field_props)

        """Use own authentication method, else use provided by Django."""
        self.authenticate_request = custom_auth

        """Use own credential extraction, else use default extractor"""
        self.get_credentials = extract_credential

    def validate(self, data):
        credentials = self.get_credentials(data)

        user = self.authenticate_request(self.context['request'], **credentials)

        if not user:
            msg = _('Unable to log in with provided credentials.')
            raise serializers.ValidationError(msg)

        payload = JSONWebTokenAuthentication.jwt_create_payload(user)

        return {
            'token': JSONWebTokenAuthentication.jwt_encode_payload(payload),
            'user': user,
            'issued_at': payload.get('iat', unix_epoch())
        }


class JSONWebTokenSerializer(BaseJSONWebTokenSerializer):
    """
    Serializer class used to validate a username and password.

    'username' is identified by the custom UserModel.USERNAME_FIELD.

    Returns a JSON Web Token that can be used to authenticate later calls.
    """

    def __init__(self, *args, **kwargs):
        fields = [
            (get_username_field()),
            ('password', {write_only: True,
                          required: True,
                          style: {'input_type': 'password'}}),
            ]
        super().__init__(*args, **kwargs, fields=fields)

    @property
    def username_field(self):
        return get_username_field()


class VerifyAuthTokenSerializer(serializers.Serializer):
    """
    Serializer used for verifying JWTs.
    """

    token = serializers.CharField(required=True)

    def validate(self, data):
        token = data['token']

        payload = _check_payload(token=token)
        user = _check_user(payload=payload)

        return {
            'token': token,
            'user': user,
            'issued_at': payload.get('iat', None)
        }


class RefreshAuthTokenSerializer(serializers.Serializer):
    """
    Serializer used for refreshing JWTs.
    """

    token = serializers.CharField(required=True)

    def validate(self, data):
        token = data['token']

        payload = _check_payload(token=token)
        user = _check_user(payload=payload)

        # Get and check 'orig_iat'
        orig_iat = payload.get('orig_iat')

        if orig_iat is None:
            msg = _('orig_iat field not found in token.')
            raise serializers.ValidationError(msg)

        # Verify expiration
        refresh_limit = \
            api_settings.JWT_REFRESH_EXPIRATION_DELTA.total_seconds()

        expiration_timestamp = orig_iat + refresh_limit
        now_timestamp = unix_epoch()

        if now_timestamp > expiration_timestamp:
            msg = _('Refresh has expired.')
            raise serializers.ValidationError(msg)

        new_payload = JSONWebTokenAuthentication.jwt_create_payload(user)
        new_payload['orig_iat'] = orig_iat

        return {
            'token':
                JSONWebTokenAuthentication.jwt_encode_payload(new_payload),
            'user':
                user,
            'issued_at':
                new_payload.get('iat', unix_epoch())
        }
