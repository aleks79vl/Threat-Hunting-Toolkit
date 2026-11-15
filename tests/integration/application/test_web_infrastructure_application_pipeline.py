import pytest

from src.application.web_infrastructure_application_pipeline import (
    run_web_infrastructure_application_pipeline,
)
from src.config.app_config import default_app_config
from src.parsers.parser_diagnostics import ParserDiagnostics


def test_web_infrastructure_application_pipeline_loads_all_sources():
    config = default_app_config()

    result = run_web_infrastructure_application_pipeline(
        apache_access_log_file=config.web_log_file,
        apache_vhost_log_file=config.apache_vhost_log_file,
        apache_error_log_file=config.apache_error_log_file,
        nginx_access_log_file=config.nginx_access_log_file,
        nginx_error_log_file=config.nginx_error_log_file,
        api_gateway_log_file=config.api_gateway_log_file,
        haproxy_log_file=config.haproxy_log_file,
        waf_cdn_log_file=config.waf_cdn_log_file,
        web_security_baseline_file=config.web_security_baseline_file,
    )

    assert result.event_statistics() == {
        "total_events": 30,
        "events_by_source": {
            "apache": 14,
            "apache_error": 3,
            "api_gateway": 3,
            "haproxy": 2,
            "nginx": 2,
            "nginx_error": 3,
            "waf_cdn": 3,
        },
    }
    assert result.findings


def test_web_infrastructure_pipeline_exposes_nginx_diagnostics(
    tmp_path,
):
    config = default_app_config()

    nginx_log = tmp_path / "nginx_mixed.jsonl"

    nginx_log.write_text(
        "\n".join([
            '{"time":"2026-10-21T10:00:00Z",'
            '"remote_addr":"192.0.2.10",'
            '"request_method":"GET",'
            '"request_uri":"/first",'
            '"status":200}',

            '["unexpected", "root"]',

            '{"time":"2026-10-21T10:00:02Z",'
            '"remote_addr":"192.0.2.20",'
            '"request_method":"GET",'
            '"request_uri":"/second",'
            '"status":200}',
        ]) + "\n",
        encoding="utf-8",
    )

    diagnostics = ParserDiagnostics(source="nginx")

    result = run_web_infrastructure_application_pipeline(
        apache_access_log_file=config.web_log_file,
        apache_vhost_log_file=config.apache_vhost_log_file,
        apache_error_log_file=config.apache_error_log_file,
        nginx_access_log_file=str(nginx_log),
        nginx_error_log_file=config.nginx_error_log_file,
        api_gateway_log_file=config.api_gateway_log_file,
        haproxy_log_file=config.haproxy_log_file,
        waf_cdn_log_file=config.waf_cdn_log_file,
        web_security_baseline_file=config.web_security_baseline_file,
        nginx_diagnostics=diagnostics,
    )

    assert diagnostics.read == 3
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 1

    assert len(diagnostics.issues) == 1
    assert diagnostics.issues[0].line_number == 2
    assert diagnostics.issues[0].reason == (
        "invalid_root_type"
    )

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )

    statistics = result.event_statistics()

    assert statistics["total_events"] == 30
    assert statistics["events_by_source"] == {
        "apache": 14,
        "apache_error": 3,
        "api_gateway": 3,
        "haproxy": 2,
        "nginx": 2,
        "nginx_error": 3,
        "waf_cdn": 3,
    }


def test_web_infrastructure_pipeline_exposes_waf_diagnostics(
    tmp_path,
    monkeypatch,
):
    import json

    import src.application.web_infrastructure_application_pipeline as pipeline
    from src.parsers.parser_diagnostics import ParserDiagnostics

    log_file = tmp_path / "waf_pipeline_diagnostics.jsonl"

    valid_record = {
        "timestamp": "2026-10-21T10:00:00Z",
        "client_ip": "192.0.2.10",
        "method": "GET",
        "path": "/first",
        "status_code": 200,
        "host": "api.example.com",
        "action": "allow",
    }

    last_record = {
        **valid_record,
        "path": "/last",
        "status_code": 403,
        "action": "block",
    }

    log_file.write_text(
        "\n".join([
            json.dumps(valid_record),
            "null",
            '{"timestamp":',
            json.dumps(last_record),
        ]) + "\n",
        encoding="utf-8",
    )

    other_parsers = (
        "parse_apache_access_log",
        "parse_apache_vhost_access_log",
        "parse_apache_error_log",
        "parse_nginx_json_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
    )

    for parser_name in other_parsers:
        monkeypatch.setattr(
            pipeline,
            parser_name,
            lambda _path, **_kwargs: [],
        )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    diagnostics = ParserDiagnostics(source="waf_cdn")

    events = pipeline.run_web_infrastructure_application_pipeline(
        apache_access_log_file="unused",
        apache_vhost_log_file="unused",
        apache_error_log_file="unused",
        nginx_access_log_file="unused",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file=str(log_file),
        web_security_baseline_file="unused",
        waf_diagnostics=diagnostics,
    )

    assert [event.path for event in events] == [
        "/first",
        "/last",
    ]

    assert diagnostics.read == 4
    assert diagnostics.accepted == 2
    assert diagnostics.rejected == 2

    assert [
        (issue.line_number, issue.reason)
        for issue in diagnostics.issues
    ] == [
        (2, "invalid_root_type"),
        (3, "invalid_json"),
    ]

    assert diagnostics.read == (
        diagnostics.accepted + diagnostics.rejected
    )


def test_web_infrastructure_pipeline_exposes_apache_diagnostics(
    tmp_path,
    monkeypatch,
):
    import src.application.web_infrastructure_application_pipeline as pipeline
    from src.parsers.parser_diagnostics import ParserDiagnostics

    apache_log = tmp_path / "apache_mixed.log"
    vhost_log = tmp_path / "apache_vhost_mixed.log"

    apache_log.write_text(
        "\n".join([
            '192.0.2.10 - - '
            '[21/Oct/2026:10:00:00 +0000] '
            '"GET /apache-first HTTP/1.1" 200 1024 '
            '"-" "pytest"',

            "",

            "invalid apache record secret=do_not_echo",

            '192.0.2.10 - - '
            '[21/Oct/2026:10:00:01 +0000] '
            '"GET /apache-last HTTP/1.1" 204 - '
            '"-" "pytest"',
        ]) + "\n",
        encoding="utf-8",
    )

    vhost_log.write_text(
        "\n".join([
            'api.example.com 192.0.2.20 - - '
            '[21/Oct/2026:10:00:02 +0000] '
            '"GET /vhost-first HTTP/1.1" 204 - '
            '"-" "pytest"',

            "invalid vhost record secret=do_not_echo",
        ]) + "\n",
        encoding="utf-8",
    )

    other_parsers = (
        "parse_apache_error_log",
        "parse_nginx_json_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
        "parse_waf_cdn_log",
    )

    for parser_name in other_parsers:
        monkeypatch.setattr(
            pipeline,
            parser_name,
            lambda _path, **_kwargs: [],
        )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    access_diagnostics = ParserDiagnostics(
        source="apache_access",
    )
    vhost_diagnostics = ParserDiagnostics(
        source="apache_vhost",
    )

    events = pipeline.run_web_infrastructure_application_pipeline(
        apache_access_log_file=str(apache_log),
        apache_vhost_log_file=str(vhost_log),
        apache_error_log_file="unused",
        nginx_access_log_file="unused",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file="unused",
        web_security_baseline_file="unused",
        apache_access_diagnostics=access_diagnostics,
        apache_vhost_diagnostics=vhost_diagnostics,
    )

    assert [event.path for event in events] == [
        "/apache-first",
        "/apache-last",
        "/vhost-first",
    ]

    assert [event.response_size for event in events] == [
        1024,
        0,
        0,
    ]

    assert access_diagnostics.read == 3
    assert access_diagnostics.accepted == 2
    assert access_diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in access_diagnostics.issues
    ] == [
        (3, "invalid_log_format"),
    ]

    assert vhost_diagnostics.read == 2
    assert vhost_diagnostics.accepted == 1
    assert vhost_diagnostics.rejected == 1

    assert [
        (issue.line_number, issue.reason)
        for issue in vhost_diagnostics.issues
    ] == [
        (2, "invalid_log_format"),
    ]

    for diagnostics in (
        access_diagnostics,
        vhost_diagnostics,
    ):
        assert diagnostics.read == (
            diagnostics.accepted + diagnostics.rejected
        )

        assert "secret=do_not_echo" not in repr(
            diagnostics.issues
        )


def test_web_pipeline_isolates_missing_apache_access_source(
    tmp_path,
    monkeypatch,
):
    import src.application.web_infrastructure_application_pipeline as pipeline

    missing_access_log = tmp_path / "missing_apache_access.log"
    vhost_log = tmp_path / "apache_vhost_valid.log"

    vhost_log.write_text(
        'api.example.com 192.0.2.20 - - '
        '[21/Oct/2026:10:00:00 +0000] '
        '"GET /vhost-survives HTTP/1.1" '
        '200 123 "-" "pytest"\n',
        encoding="utf-8",
    )

    assert not missing_access_log.exists()

    other_parsers = (
        "parse_apache_error_log",
        "parse_nginx_json_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
        "parse_waf_cdn_log",
    )

    for parser_name in other_parsers:
        monkeypatch.setattr(
            pipeline,
            parser_name,
            lambda _path, **_kwargs: [],
        )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    source_failures = []

    events = pipeline.run_web_infrastructure_application_pipeline(
        apache_access_log_file=str(missing_access_log),
        apache_vhost_log_file=str(vhost_log),
        apache_error_log_file="unused",
        nginx_access_log_file="unused",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file="unused",
        web_security_baseline_file="unused",
        source_failures=source_failures,
    )

    assert [event.path for event in events] == [
        "/vhost-survives",
    ]

    assert [event.response_size for event in events] == [
        123,
    ]

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("apache_access", "file_not_found"),
    ]

    assert str(missing_access_log) not in repr(
        source_failures
    )


def test_web_pipeline_isolates_permission_denied_apache_access(
    tmp_path,
    monkeypatch,
):
    import src.application.web_infrastructure_application_pipeline as pipeline

    vhost_log = tmp_path / "apache_vhost_valid.log"

    vhost_log.write_text(
        'api.example.com 192.0.2.20 - - '
        '[21/Oct/2026:10:00:00 +0000] '
        '"GET /vhost-survives HTTP/1.1" '
        '200 123 "-" "pytest"\n',
        encoding="utf-8",
    )

    def denied_access(_path, *, diagnostics=None):
        raise PermissionError(
            "sensitive=/private/internal/apache.log"
        )

    monkeypatch.setattr(
        pipeline,
        "parse_apache_access_log",
        denied_access,
    )

    other_parsers = (
        "parse_apache_error_log",
        "parse_nginx_json_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
        "parse_waf_cdn_log",
    )

    for parser_name in other_parsers:
        monkeypatch.setattr(
            pipeline,
            parser_name,
            lambda _path, **_kwargs: [],
        )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    source_failures = []

    events = pipeline.run_web_infrastructure_application_pipeline(
        apache_access_log_file="restricted",
        apache_vhost_log_file=str(vhost_log),
        apache_error_log_file="unused",
        nginx_access_log_file="unused",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file="unused",
        web_security_baseline_file="unused",
        source_failures=source_failures,
    )

    assert [event.path for event in events] == [
        "/vhost-survives",
    ]

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("apache_access", "permission_denied"),
    ]

    assert "sensitive=" not in repr(source_failures)
    assert "/private/internal" not in repr(source_failures)


@pytest.mark.parametrize(
    ("exception_type", "expected_reason"),
    [
        (FileNotFoundError, "file_not_found"),
        (PermissionError, "permission_denied"),
    ],
    ids=["file_not_found", "permission_denied"],
)
def test_web_pipeline_isolates_apache_vhost_failure(
    tmp_path,
    monkeypatch,
    exception_type,
    expected_reason,
):
    import src.application.web_infrastructure_application_pipeline as pipeline
    from src.parsers.parser_diagnostics import ParserDiagnostics

    access_log = tmp_path / "apache_access_valid.log"

    access_log.write_text(
        '192.0.2.10 - - '
        '[21/Oct/2026:10:00:00 +0000] '
        '"GET /access-survives HTTP/1.1" '
        '200 256 "-" "pytest"\n',
        encoding="utf-8",
    )

    def failed_vhost(_path, *, diagnostics=None):
        raise exception_type(
            "sensitive=/private/internal/vhost.log"
        )

    monkeypatch.setattr(
        pipeline,
        "parse_apache_vhost_access_log",
        failed_vhost,
    )

    other_parsers = (
        "parse_apache_error_log",
        "parse_nginx_json_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
        "parse_waf_cdn_log",
    )

    for parser_name in other_parsers:
        monkeypatch.setattr(
            pipeline,
            parser_name,
            lambda _path, **_kwargs: [],
        )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    source_failures = []

    access_diagnostics = ParserDiagnostics(
        source="apache_access",
    )

    events = pipeline.run_web_infrastructure_application_pipeline(
        apache_access_log_file=str(access_log),
        apache_vhost_log_file="restricted",
        apache_error_log_file="unused",
        nginx_access_log_file="unused",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file="unused",
        web_security_baseline_file="unused",
        apache_access_diagnostics=access_diagnostics,
        source_failures=source_failures,
    )

    assert [event.path for event in events] == [
        "/access-survives",
    ]

    assert [event.response_size for event in events] == [
        256,
    ]

    assert (
        access_diagnostics.read,
        access_diagnostics.accepted,
        access_diagnostics.rejected,
    ) == (1, 1, 0)

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("apache_vhost", expected_reason),
    ]

    assert "sensitive=" not in repr(source_failures)
    assert "/private/internal" not in repr(source_failures)


def test_web_pipeline_preserves_healthy_sources_when_both_apache_sources_fail(
    tmp_path,
    monkeypatch,
):
    import src.application.web_infrastructure_application_pipeline as pipeline

    missing_access = tmp_path / "missing_access.log"
    missing_vhost = tmp_path / "missing_vhost.log"

    assert not missing_access.exists()
    assert not missing_vhost.exists()

    nginx_event = object()
    waf_event = object()

    monkeypatch.setattr(
        pipeline,
        "parse_nginx_json_log",
        lambda _path, *, diagnostics=None: [nginx_event],
    )

    monkeypatch.setattr(
        pipeline,
        "parse_waf_cdn_log",
        lambda _path, *, diagnostics=None: [waf_event],
    )

    other_parsers = (
        "parse_apache_error_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
    )

    for parser_name in other_parsers:
        monkeypatch.setattr(
            pipeline,
            parser_name,
            lambda _path, **_kwargs: [],
        )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    source_failures = []

    events = pipeline.run_web_infrastructure_application_pipeline(
        apache_access_log_file=str(missing_access),
        apache_vhost_log_file=str(missing_vhost),
        apache_error_log_file="unused",
        nginx_access_log_file="unused",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file="unused",
        web_security_baseline_file="unused",
        source_failures=source_failures,
    )

    assert len(events) == 2
    assert events[0] is nginx_event
    assert events[1] is waf_event

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("apache_access", "file_not_found"),
        ("apache_vhost", "file_not_found"),
    ]

    assert str(missing_access) not in repr(source_failures)
    assert str(missing_vhost) not in repr(source_failures)


@pytest.mark.parametrize(
    ("exception_type", "expected_reason"),
    [
        (FileNotFoundError, "file_not_found"),
        (PermissionError, "permission_denied"),
    ],
    ids=["file_not_found", "permission_denied"],
)
def test_web_pipeline_isolates_nginx_source_failure(
    monkeypatch,
    exception_type,
    expected_reason,
):
    import src.application.web_infrastructure_application_pipeline as pipeline

    def failed_nginx(_path, *, diagnostics=None):
        raise exception_type(
            "sensitive=/private/internal/nginx.jsonl"
        )

    monkeypatch.setattr(
        pipeline,
        "parse_nginx_json_log",
        failed_nginx,
    )

    waf_event = object()

    monkeypatch.setattr(
        pipeline,
        "parse_waf_cdn_log",
        lambda _path, *, diagnostics=None: [waf_event],
    )

    other_parsers = (
        "parse_apache_access_log",
        "parse_apache_vhost_access_log",
        "parse_apache_error_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
    )

    for parser_name in other_parsers:
        monkeypatch.setattr(
            pipeline,
            parser_name,
            lambda _path, **_kwargs: [],
        )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    source_failures = []

    events = pipeline.run_web_infrastructure_application_pipeline(
        apache_access_log_file="unused",
        apache_vhost_log_file="unused",
        apache_error_log_file="unused",
        nginx_access_log_file="restricted",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file="unused",
        web_security_baseline_file="unused",
        source_failures=source_failures,
    )

    assert len(events) == 1
    assert events[0] is waf_event

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("nginx", expected_reason),
    ]

    assert "sensitive=" not in repr(source_failures)
    assert "/private/internal" not in repr(source_failures)


@pytest.mark.parametrize(
    ("exception_type", "expected_reason"),
    [
        (FileNotFoundError, "file_not_found"),
        (PermissionError, "permission_denied"),
    ],
    ids=["file_not_found", "permission_denied"],
)
def test_web_pipeline_isolates_waf_source_failure(
    monkeypatch,
    exception_type,
    expected_reason,
):
    import src.application.web_infrastructure_application_pipeline as pipeline

    def failed_waf(_path, *, diagnostics=None):
        raise exception_type(
            "sensitive=/private/internal/waf.jsonl"
        )

    monkeypatch.setattr(
        pipeline,
        "parse_waf_cdn_log",
        failed_waf,
    )

    nginx_event = object()

    monkeypatch.setattr(
        pipeline,
        "parse_nginx_json_log",
        lambda _path, *, diagnostics=None: [nginx_event],
    )

    other_parsers = (
        "parse_apache_access_log",
        "parse_apache_vhost_access_log",
        "parse_apache_error_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
    )

    for parser_name in other_parsers:
        monkeypatch.setattr(
            pipeline,
            parser_name,
            lambda _path, **_kwargs: [],
        )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    source_failures = []

    events = pipeline.run_web_infrastructure_application_pipeline(
        apache_access_log_file="unused",
        apache_vhost_log_file="unused",
        apache_error_log_file="unused",
        nginx_access_log_file="healthy",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file="restricted",
        web_security_baseline_file="unused",
        source_failures=source_failures,
    )

    assert len(events) == 1
    assert events[0] is nginx_event

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("waf_cdn", expected_reason),
    ]

    assert "sensitive=" not in repr(source_failures)
    assert "/private/internal" not in repr(source_failures)


@pytest.mark.parametrize(
    ("parser_name", "source_name"),
    [
        ("parse_apache_error_log", "apache_error"),
        ("parse_nginx_error_log", "nginx_error"),
        ("parse_api_gateway_log", "api_gateway"),
        ("parse_haproxy_http_log", "haproxy"),
    ],
)
@pytest.mark.parametrize(
    ("exception_type", "expected_reason"),
    [
        (FileNotFoundError, "file_not_found"),
        (PermissionError, "permission_denied"),
    ],
)
def test_web_pipeline_isolates_remaining_source_failures(
    monkeypatch,
    parser_name,
    source_name,
    exception_type,
    expected_reason,
):
    import src.application.web_infrastructure_application_pipeline as pipeline

    all_parsers = (
        "parse_apache_access_log",
        "parse_apache_vhost_access_log",
        "parse_apache_error_log",
        "parse_nginx_json_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
        "parse_waf_cdn_log",
    )

    for name in all_parsers:
        monkeypatch.setattr(
            pipeline,
            name,
            lambda _path, **_kwargs: [],
        )

    waf_event = object()

    monkeypatch.setattr(
        pipeline,
        "parse_waf_cdn_log",
        lambda _path, **_kwargs: [waf_event],
    )

    def failed_parser(_path, **_kwargs):
        raise exception_type(
            "sensitive=/private/internal/source.log"
        )

    monkeypatch.setattr(
        pipeline,
        parser_name,
        failed_parser,
    )

    monkeypatch.setattr(
        pipeline,
        "load_web_security_baseline",
        lambda _path: None,
    )

    monkeypatch.setattr(
        pipeline,
        "run_web_infrastructure_detection_pipeline",
        lambda events, *, web_security_baseline: events,
    )

    pipeline_args = dict(
        apache_access_log_file="unused",
        apache_vhost_log_file="unused",
        apache_error_log_file="unused",
        nginx_access_log_file="unused",
        nginx_error_log_file="unused",
        api_gateway_log_file="unused",
        haproxy_log_file="unused",
        waf_cdn_log_file="unused",
        web_security_baseline_file="unused",
    )

    with pytest.raises(exception_type):
        pipeline.run_web_infrastructure_application_pipeline(
            **pipeline_args,
        )

    source_failures = []

    events = pipeline.run_web_infrastructure_application_pipeline(
        **pipeline_args,
        source_failures=source_failures,
    )

    assert len(events) == 1
    assert events[0] is waf_event

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        (source_name, expected_reason),
    ]

    assert "sensitive=" not in repr(source_failures)
    assert "/private/internal" not in repr(source_failures)


@pytest.mark.parametrize(
    "parser_name",
    [
        "parse_apache_access_log",
        "parse_apache_vhost_access_log",
        "parse_apache_error_log",
        "parse_nginx_json_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
        "parse_waf_cdn_log",
    ],
)
@pytest.mark.parametrize(
    "exception_type",
    [ValueError, TypeError],
    ids=["value_error", "type_error"],
)
def test_web_pipeline_does_not_suppress_programming_errors(
    monkeypatch,
    parser_name,
    exception_type,
):
    import src.application.web_infrastructure_application_pipeline as pipeline

    all_parsers = (
        "parse_apache_access_log",
        "parse_apache_vhost_access_log",
        "parse_apache_error_log",
        "parse_nginx_json_log",
        "parse_nginx_error_log",
        "parse_api_gateway_log",
        "parse_haproxy_http_log",
        "parse_waf_cdn_log",
    )

    for name in all_parsers:
        monkeypatch.setattr(
            pipeline,
            name,
            lambda _path, **_kwargs: [],
        )

    def broken_parser(_path, **_kwargs):
        raise exception_type(
            "programming_error_do_not_echo"
        )

    monkeypatch.setattr(
        pipeline,
        parser_name,
        broken_parser,
    )

    source_failures = []

    with pytest.raises(
        exception_type,
        match="programming_error_do_not_echo",
    ):
        pipeline.run_web_infrastructure_application_pipeline(
            apache_access_log_file="unused",
            apache_vhost_log_file="unused",
            apache_error_log_file="unused",
            nginx_access_log_file="unused",
            nginx_error_log_file="unused",
            api_gateway_log_file="unused",
            haproxy_log_file="unused",
            waf_cdn_log_file="unused",
            web_security_baseline_file="unused",
            source_failures=source_failures,
        )

    assert source_failures == []
