"""Tests for authentication logic in the openHAB config model and connection handler."""
from __future__ import annotations

from base64 import b64encode

import pytest
from pydantic import ValidationError

from HABApp.config.models.openhab import Connection


class TestBuildToken:
    """Tests for the token/auth resolution of the openHAB Connection config model."""

    def test_token_in_explicit_field(self):
        conn = Connection(url='http://localhost:8080', token='oh.mytoken.abc')
        assert conn.build_url_token() == 'oh.mytoken.abc'
        assert conn.build_basic_auth_header() == (('Authorization', 'Bearer oh.mytoken.abc'), )

    def test_token_in_login(self):
        conn = Connection(user='oh.mytoken.abc')
        assert conn.build_url_token() == 'oh.mytoken.abc'

    def test_basic_auth_fallback(self):
        conn = Connection(user='admin', password='secret')
        expected = b64encode(b'admin:secret').decode()
        assert conn.build_url_token() == expected

    def test_explicit_token_takes_precedence_over_user(self):
        conn = Connection(token='oh.explicit', user='oh.user_token')
        assert conn.build_url_token() == 'oh.explicit'


class TestTokenResolution:
    """Tests for the token resolution logic used when establishing the openHAB connection.

    An explicit token field is used as Bearer token. An openHAB access token in the "user"
    field is treated as token as well. Plain user/password credentials fall back to basic auth.
    """

    def test_explicit_token_field(self):
        cfg = Connection(token='oh.explicit.token')
        assert cfg.auth_complete()
        assert cfg.build_basic_auth_header() == (('Authorization', 'Bearer oh.explicit.token'), )

    def test_token_in_user_migrated(self):
        """Token placed in 'user' is detected and used for authentication."""
        cfg = Connection(user='oh.legacy_user_token')
        assert cfg.auth_complete()
        assert cfg.build_url_token() == 'oh.legacy_user_token'

    def test_token_in_password_is_error(self):
        """Token placed in 'password' is rejected with a validation error."""
        with pytest.raises(ValidationError):
            Connection(password='oh.legacy_pass_token')

    def test_explicit_token_takes_precedence_over_user(self):
        """Explicit token field wins; no migration flag when both are set."""
        cfg = Connection(token='oh.explicit', user='oh.user_token')
        assert cfg.build_basic_auth_header() == (('Authorization', 'Bearer oh.explicit'), )

    def test_plain_credentials_no_token(self):
        """Plain username/password: no bearer token resolved, basic auth is used."""
        cfg = Connection(user='admin', password='secret')
        assert cfg.auth_complete()
        header = cfg.build_basic_auth_header()[0][1]
        assert header.startswith('Basic ')
        assert b64encode(b'admin:secret').decode() in header

    def test_no_credentials_not_auth_complete(self):
        assert not Connection().auth_complete()