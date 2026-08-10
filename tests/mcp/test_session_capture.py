"""Tests for strix.mcp.session_capture."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from strix.mcp.session_capture import (
    AuthenticatedSession,
    SessionCapture,
    build_cookie_header,
    extract_jwts_from_text,
    format_session_for_prompt,
    inject_session_headers,
    is_auth_header,
    is_session_cookie,
)


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


# Build a minimal syntactically-valid JWT from scratch so the file
# never contains a literal token-like string that could be masked.
_JWT_HEADER = _b64url('{"alg":"none","typ":"JWT"}')       # starts with eyJ
_JWT_PAYLOAD = _b64url('{"sub":"1234567890"}')             # starts with eyJ
_JWT_SIG = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
_FAKE_JWT = f"{_JWT_HEADER}.{_JWT_PAYLOAD}.{_JWT_SIG}"


class TestAuthenticatedSession:
    def test_is_authenticated_empty(self):
        s = AuthenticatedSession()
        assert s.is_authenticated is False

    def test_is_authenticated_with_cookie(self):
        s = AuthenticatedSession(cookies={"JSESSIONID": "abc123"})
        assert s.is_authenticated is True

    def test_is_authenticated_with_header(self):
        s = AuthenticatedSession(headers={"Authorization": "******"})
        assert s.is_authenticated is True

    def test_summary_empty(self):
        s = AuthenticatedSession()
        assert "No authenticated session" in s.summary()

    def test_summary_with_data(self):
        s = AuthenticatedSession(
            cookies={"PHPSESSID": "x"},
            headers={"Authorization": "******"},
        )
        summary = s.summary()
        assert "PHPSESSID" in summary
        assert "Authorization" in summary


class TestSessionCapture:
    def test_has_session_empty(self):
        cap = SessionCapture()
        assert cap.has_session() is False

    def test_ingest_request_headers_auth(self):
        cap = SessionCapture()
        cap.ingest_request_headers({"Authorization": "Bearer " + _FAKE_JWT})
        assert "Authorization" in cap._headers
        assert cap.has_session() is True

    def test_ingest_request_headers_ignores_plain(self):
        cap = SessionCapture()
        cap.ingest_request_headers({"Content-Type": "application/json"})
        assert cap.has_session() is False

    def test_ingest_response_headers_set_cookie(self):
        cap = SessionCapture()
        cap.ingest_response_headers({"Set-Cookie": "JSESSIONID=abc123; Path=/"})
        assert cap._cookies.get("JSESSIONID") == "abc123"
        assert cap.has_session() is True

    def test_ingest_response_headers_non_session_cookie(self):
        cap = SessionCapture()
        cap.ingest_response_headers({"Set-Cookie": "lang=en; Path=/"})
        # lang is not a session cookie name, so has_session stays False
        assert cap.has_session() is False
        # but the cookie is still stored
        assert cap._cookies.get("lang") == "en"

    def test_ingest_cookies_dict_session_cookie(self):
        cap = SessionCapture()
        cap.ingest_cookies_dict({"session": "tok123", "irrelevant": "x"})
        assert cap.has_session() is True

    def test_ingest_response_body_jwt(self):
        cap = SessionCapture()
        cap.ingest_response_body(f'{{"access_token": "{_FAKE_JWT}"}}')
        assert len(cap._jwt_tokens) == 1
        assert cap._jwt_tokens[0] == _FAKE_JWT

    def test_build_session_snapshot(self):
        cap = SessionCapture()
        cap.ingest_cookies_dict({"JSESSIONID": "sess1"})
        cap.ingest_request_headers({"X-Auth-Token": "token1"})
        session = cap.build_session()
        assert session.cookies["JSESSIONID"] == "sess1"
        assert session.headers["X-Auth-Token"] == "token1"
        assert session.session_id == "sess1"
        assert isinstance(session.detected_at, datetime)

    def test_build_session_no_mutation(self):
        cap = SessionCapture()
        cap.ingest_cookies_dict({"JSESSIONID": "a"})
        s1 = cap.build_session()
        cap.ingest_cookies_dict({"JSESSIONID": "b"})
        s2 = cap.build_session()
        assert s1.cookies["JSESSIONID"] == "a"
        assert s2.cookies["JSESSIONID"] == "b"

    def test_clear(self):
        cap = SessionCapture()
        cap.ingest_cookies_dict({"session": "x"})
        cap.clear()
        assert cap.has_session() is False
        assert cap.request_count == 0

    def test_request_count_increments(self):
        cap = SessionCapture()
        cap.ingest_request_headers({})
        cap.ingest_request_headers({})
        assert cap.request_count == 2

    def test_extract_target_domain(self):
        assert SessionCapture.extract_target_domain("https://example.com/path") == "example.com"


class TestHelpers:
    def test_is_session_cookie(self):
        assert is_session_cookie("JSESSIONID") is True
        assert is_session_cookie("jsessionid") is True
        assert is_session_cookie("PHPSESSID") is True
        assert is_session_cookie("x-custom-value") is False

    def test_is_auth_header(self):
        assert is_auth_header("Authorization") is True
        assert is_auth_header("authorization") is True
        assert is_auth_header("x-auth-token") is True
        assert is_auth_header("content-type") is False

    def test_build_cookie_header(self):
        result = build_cookie_header({"a": "1", "b": "2"})
        assert "a=1" in result
        assert "b=2" in result
        assert "; " in result

    def test_extract_jwts_from_text(self):
        text = f"Some text with token: {_FAKE_JWT} and more"
        found = extract_jwts_from_text(text)
        assert found == [_FAKE_JWT]

    def test_extract_jwts_from_text_empty(self):
        assert extract_jwts_from_text("no jwt here") == []

    def test_inject_session_headers_cookies(self):
        session = AuthenticatedSession(cookies={"session": "abc"})
        original = {"Content-Type": "application/json"}
        result = inject_session_headers(original, session)
        assert "Cookie" in result
        assert "session=abc" in result["Cookie"]
        assert result["Content-Type"] == "application/json"

    def test_inject_session_headers_auth(self):
        session = AuthenticatedSession(headers={"Authorization": "******"})
        result = inject_session_headers({}, session)
        assert result["Authorization"] == "******"

    def test_inject_session_headers_appends_to_existing_cookie(self):
        session = AuthenticatedSession(cookies={"session": "abc"})
        original = {"Cookie": "existing=x"}
        result = inject_session_headers(original, session)
        assert "existing=x" in result["Cookie"]
        assert "session=abc" in result["Cookie"]

    def test_format_session_for_prompt_empty(self):
        session = AuthenticatedSession()
        assert format_session_for_prompt(session) == ""

    def test_format_session_for_prompt_with_data(self):
        session = AuthenticatedSession(
            cookies={"JSESSIONID": "abc"},
            headers={"Authorization": "******"},
            jwt_tokens=[_FAKE_JWT],
            notes=["JWT found in response body"],
        )
        result = format_session_for_prompt(session)
        assert "[Authenticated Session Detected]" in result
        assert "JSESSIONID" in result
        assert "Authorization" in result
        assert "1 found" in result
