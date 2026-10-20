from src.security.redaction import redact_data


def test_redact_data_masks_password_without_mutating_source():
    original = {
        "username": "admin",
        "password": "SuperSecret123!",
        "source_ip": "192.168.1.100",
    }

    result = redact_data(original)

    assert result == {
        "username": "admin",
        "password": "[REDACTED]",
        "source_ip": "192.168.1.100",
    }

    assert original["password"] == "SuperSecret123!"
    assert result is not original


def test_redact_data_masks_password_case_insensitive():
    original = {
        "password": "secret1",
        "Password": "secret2",
        "PASSWORD": "secret3",
        "PassWord": "secret4",
        "username": "admin",
    }

    result = redact_data(original)

    assert result == {
        "password": "[REDACTED]",
        "Password": "[REDACTED]",
        "PASSWORD": "[REDACTED]",
        "PassWord": "[REDACTED]",
        "username": "admin",
    }

    assert original["password"] == "secret1"
    assert original["Password"] == "secret2"
    assert original["PASSWORD"] == "secret3"
    assert original["PassWord"] == "secret4"

def test_redact_data_masks_sensitive_fields():
    original = {
        "username": "admin",
        "source_ip": "192.168.1.100",
        "api_key": "sk-test-123456",
        "access_token": "eyJhbGciOiJIUzI1NiJ9",
        "authorization": "Bearer secret-token",
        "cookie": "session_id=abc123",
    }

    result = redact_data(original)

    assert result == {
        "username": "admin",
        "source_ip": "192.168.1.100",
        "api_key": "[REDACTED]",
        "access_token": "[REDACTED]",
        "authorization": "[REDACTED]",
        "cookie": "[REDACTED]",
    }

    assert original["api_key"] == "sk-test-123456"
    assert original["authorization"] == "Bearer secret-token"

def test_redact_data_masks_nested_sensitive_fields():
    original = {
        "source_ip": "192.168.1.100",
        "metadata": {
            "username": "admin",
            "password": "Secret123!",
            "authentication": {
                "api_key": "sk-test-123456",
                "access_token": "token-987",
            },
        },
    }

    result = redact_data(original)

    assert result == {
        "source_ip": "192.168.1.100",
        "metadata": {
            "username": "admin",
            "password": "[REDACTED]",
            "authentication": {
                "api_key": "[REDACTED]",
                "access_token": "[REDACTED]",
            },
        },
    }

    assert original["metadata"]["password"] == "Secret123!"
    assert original["metadata"]["authentication"]["api_key"] == "sk-test-123456"
    assert result["metadata"] is not original["metadata"]

def test_redact_data_masks_sensitive_fields_inside_lists():
    original = {
        "source_ip": "192.168.1.100",
        "events": [
            {
                "username": "admin",
                "password": "Secret123!",
            },
            {
                "username": "guest",
                "api_key": "sk-test-456",
            },
        ],
    }

    result = redact_data(original)

    assert result == {
        "source_ip": "192.168.1.100",
        "events": [
            {
                "username": "admin",
                "password": "[REDACTED]",
            },
            {
                "username": "guest",
                "api_key": "[REDACTED]",
            },
        ],
    }

    assert original["events"][0]["password"] == "Secret123!"
    assert original["events"][1]["api_key"] == "sk-test-456"
    assert result["events"] is not original["events"]

def test_redact_data_masks_sensitive_fields_in_nested_lists():
    original = {
        "source_ip": "192.168.1.100",
        "events": [
            [
                {
                    "username": "admin",
                    "password": "Secret123!",
                }
            ],
            [
                {
                    "api_key": "sk-test-456",
                    "severity": "high",
                }
            ],
        ],
    }

    result = redact_data(original)

    assert result == {
        "source_ip": "192.168.1.100",
        "events": [
            [
                {
                    "username": "admin",
                    "password": "[REDACTED]",
                }
            ],
            [
                {
                    "api_key": "[REDACTED]",
                    "severity": "high",
                }
            ],
        ],
    }

    assert original["events"][0][0]["password"] == "Secret123!"
    assert original["events"][1][0]["api_key"] == "sk-test-456"
    assert result["events"] is not original["events"]
    assert result["events"][0] is not original["events"][0]

def test_redact_data_masks_password_inside_raw_event():
    original = {
        "source_ip": "192.168.1.100",
        "raw_event": (
            "Login failed user=admin "
            "password=Secret123! "
            "source_ip=192.168.1.100"
        ),
    }

    result = redact_data(original)

    assert result == {
        "source_ip": "192.168.1.100",
        "raw_event": (
            "Login failed user=admin "
            "password=[REDACTED] "
            "source_ip=192.168.1.100"
        ),
    }

    assert "password=Secret123!" in original["raw_event"]
    assert "Secret123!" not in result["raw_event"]

def test_redact_data_masks_quoted_password_with_spaces():
    original = {
        "raw_event": (
            'Login failed password="My Secret 123!" '
            'source_ip=192.168.1.100'
        ),
    }

    result = redact_data(original)

    assert result == {
        "raw_event": (
            'Login failed password="[REDACTED]" '
            'source_ip=192.168.1.100'
        ),
    }

    assert 'password="My Secret 123!"' in original["raw_event"]
    assert "My Secret 123!" not in result["raw_event"]
    assert "source_ip=192.168.1.100" in result["raw_event"]

def test_redact_data_masks_bearer_token_inside_raw_event():
    original = {
        "raw_event": (
            "GET /admin HTTP/1.1 "
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9"
        ),
    }

    result = redact_data(original)

    assert result == {
        "raw_event": (
            "GET /admin HTTP/1.1 "
            "Authorization: Bearer [REDACTED]"
        ),
    }

    assert "eyJhbGciOiJIUzI1NiJ9" in original["raw_event"]
    assert "eyJhbGciOiJIUzI1NiJ9" not in result["raw_event"]
    assert "GET /admin HTTP/1.1" in result["raw_event"]

def test_redact_data_masks_cookie_header_inside_raw_event():
    original = {
        "raw_event": (
            "GET /dashboard HTTP/1.1\n"
            "Cookie: session_id=abc123; theme=dark\n"
            "User-Agent: Mozilla/5.0"
        ),
    }

    result = redact_data(original)

    assert result == {
        "raw_event": (
            "GET /dashboard HTTP/1.1\n"
            "Cookie: [REDACTED]\n"
            "User-Agent: Mozilla/5.0"
        ),
    }

    assert "session_id=abc123" in original["raw_event"]
    assert "session_id=abc123" not in result["raw_event"]
    assert "GET /dashboard HTTP/1.1" in result["raw_event"]
    assert "User-Agent: Mozilla/5.0" in result["raw_event"]

def test_redact_data_masks_set_cookie_header_inside_raw_event():
    original = {
        "raw_event": (
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: session_id=abc123; HttpOnly; Secure\n"
            "Content-Type: text/html"
        ),
    }

    result = redact_data(original)

    assert result == {
        "raw_event": (
            "HTTP/1.1 200 OK\n"
            "Set-Cookie: [REDACTED]\n"
            "Content-Type: text/html"
        ),
    }

    assert "session_id=abc123" in original["raw_event"]
    assert "session_id=abc123" not in result["raw_event"]
    assert "HTTP/1.1 200 OK" in result["raw_event"]
    assert "Content-Type: text/html" in result["raw_event"]

def test_redact_data_masks_api_key_inside_raw_event():
    original = {
        "raw_event": (
            "GET /api/users "
            "api_key=sk-test-123456 "
            "source_ip=192.168.1.100"
        ),
    }

    result = redact_data(original)

    assert result == {
        "raw_event": (
            "GET /api/users "
            "api_key=[REDACTED] "
            "source_ip=192.168.1.100"
        ),
    }

    assert "sk-test-123456" in original["raw_event"]
    assert "sk-test-123456" not in result["raw_event"]
    assert "GET /api/users" in result["raw_event"]
    assert "source_ip=192.168.1.100" in result["raw_event"]

def test_redact_data_masks_access_token_inside_raw_event():
    original = {
        "raw_event": (
            "POST /auth/login "
            "access_token=secret-token-123 "
            "source_ip=192.168.1.100"
        ),
    }

    result = redact_data(original)

    assert result == {
        "raw_event": (
            "POST /auth/login "
            "access_token=[REDACTED] "
            "source_ip=192.168.1.100"
        ),
    }

    assert "secret-token-123" in original["raw_event"]
    assert "secret-token-123" not in result["raw_event"]
    assert "POST /auth/login" in result["raw_event"]
    assert "source_ip=192.168.1.100" in result["raw_event"]

def test_export_redaction_hides_unknown_raw_event():
    from src.security.redaction import redact_for_export

    original = {
        "source_ip": "192.168.1.100",
        "severity": "high",
        "raw_event": (
            "Authentication failed "
            "credential: UltraSecret987!"
        ),
    }

    result = redact_for_export(original)

    assert result == {
        "source_ip": "192.168.1.100",
        "severity": "high",
    }

    assert "UltraSecret987!" in original["raw_event"]
    assert "UltraSecret987!" not in str(result)
    assert result is not original

def test_export_redaction_hides_nested_raw_event():
    from src.security.redaction import redact_for_export

    original = {
        "source_ip": "192.168.1.100",
        "metadata": {
            "severity": "high",
            "raw_event": "credential: UltraSecret987!",
        },
    }

    result = redact_for_export(original)

    assert result == {
        "source_ip": "192.168.1.100",
        "metadata": {
            "severity": "high",
        },
    }

    assert original["metadata"]["raw_event"] == (
        "credential: UltraSecret987!"
    )

    assert "UltraSecret987!" not in str(result)
    assert result["metadata"] is not original["metadata"]

def test_export_redaction_hides_raw_event_inside_lists():
    from src.security.redaction import redact_for_export

    original = {
        "events": [
            {
                "source_ip": "192.168.1.100",
                "raw_event": "credential: UltraSecret987!",
            },
            {
                "source_ip": "10.0.0.5",
                "raw_event": "token: AnotherSecret123!",
            },
        ]
    }

    result = redact_for_export(original)

    assert result == {
        "events": [
            {
                "source_ip": "192.168.1.100",
            },
            {
                "source_ip": "10.0.0.5",
            },
        ]
    }

    assert "UltraSecret987!" not in str(result)
    assert "AnotherSecret123!" not in str(result)

    assert original["events"][0]["raw_event"] == (
        "credential: UltraSecret987!"
    )