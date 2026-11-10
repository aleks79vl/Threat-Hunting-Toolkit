import pytest

def test_traditional_pipeline_isolates_missing_firewall_source(
    monkeypatch,
):
    import src.application.traditional_detection_pipeline as pipeline

    monkeypatch.setattr(
        pipeline, "parse_nmap_xml", lambda _path: []
    )
    monkeypatch.setattr(
        pipeline, "detect_unknown_ips",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        pipeline, "detect_critical_ports",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        pipeline, "correlate_threats",
        lambda *args, **kwargs: [],
    )

    monkeypatch.setattr(
        pipeline, "parse_windows_events", lambda _path: []
    )
    monkeypatch.setattr(
        pipeline, "detect_windows_events",
        lambda *args, **kwargs: [],
    )

    def missing_firewall(_path, *, diagnostics=None):
        raise FileNotFoundError(
            "sensitive=/private/internal/firewall.log"
        )

    monkeypatch.setattr(
        pipeline,
        "parse_firewall_log",
        missing_firewall,
    )

    monkeypatch.setattr(
        pipeline,
        "detect_firewall_events",
        lambda *args, **kwargs: [],
    )

    web_event = object()
    web_finding = object()

    monkeypatch.setattr(
        pipeline,
        "parse_web_log",
        lambda _path: [web_event],
    )

    def detect_web(events):
        assert events == [web_event]
        return [web_finding]

    monkeypatch.setattr(
        pipeline,
        "detect_web_attacks",
        detect_web,
    )

    source_failures = []

    result = pipeline.run_traditional_detection_pipeline(
        nmap_file="unused",
        windows_events_file="unused",
        firewall_file="restricted",
        web_log_file="healthy",
        whitelist_file="unused",
        critical_ports_file="unused",
        source_failures=source_failures,
    )

    assert result.web_findings == [web_finding]

    assert result.firewall_events == []

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("firewall", "file_not_found"),
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
def test_traditional_pipeline_isolates_windows_source_failure(
    monkeypatch,
    exception_type,
    expected_reason,
):
    import src.application.traditional_detection_pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "parse_nmap_xml",
        lambda _path: [],
    )
    monkeypatch.setattr(
        pipeline,
        "detect_unknown_ips",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        pipeline,
        "detect_critical_ports",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        pipeline,
        "correlate_threats",
        lambda *args, **kwargs: [],
    )

    def failed_windows(_path):
        raise exception_type(
            "sensitive=/private/internal/windows.json"
        )

    monkeypatch.setattr(
        pipeline,
        "parse_windows_events",
        failed_windows,
    )
    monkeypatch.setattr(
        pipeline,
        "detect_windows_events",
        lambda *args, **kwargs: [],
    )

    firewall_event = object()
    firewall_finding = object()

    monkeypatch.setattr(
        pipeline,
        "parse_firewall_log",
        lambda _path, *, diagnostics=None: [firewall_event],
    )

    def detect_firewall(events, **kwargs):
        assert events == [firewall_event]
        return [firewall_finding]

    monkeypatch.setattr(
        pipeline,
        "detect_firewall_events",
        detect_firewall,
    )

    web_event = object()
    web_finding = object()

    monkeypatch.setattr(
        pipeline,
        "parse_web_log",
        lambda _path: [web_event],
    )

    def detect_web(events):
        assert events == [web_event]
        return [web_finding]

    monkeypatch.setattr(
        pipeline,
        "detect_web_attacks",
        detect_web,
    )

    pipeline_args = dict(
        nmap_file="unused",
        windows_events_file="restricted",
        firewall_file="healthy",
        web_log_file="healthy",
        whitelist_file="unused",
        critical_ports_file="unused",
    )

    with pytest.raises(exception_type):
        pipeline.run_traditional_detection_pipeline(
            **pipeline_args,
        )

    source_failures = []

    result = pipeline.run_traditional_detection_pipeline(
        **pipeline_args,
        source_failures=source_failures,
    )

    assert result.windows_findings == []

    assert result.firewall_events == [firewall_event]
    assert result.firewall_findings == [firewall_finding]
    assert result.web_findings == [web_finding]

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("windows_events", expected_reason),
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
def test_traditional_pipeline_isolates_nmap_source_failure(
    monkeypatch,
    exception_type,
    expected_reason,
):
    import src.application.traditional_detection_pipeline as pipeline

    def failed_nmap(_path):
        raise exception_type(
            "sensitive=/private/internal/nmap.xml"
        )

    monkeypatch.setattr(
        pipeline,
        "parse_nmap_xml",
        failed_nmap,
    )

    def unexpected_nmap_detection(*args, **kwargs):
        raise AssertionError(
            "Nmap detection ran without Nmap telemetry"
        )

    for name in (
        "detect_unknown_ips",
        "detect_critical_ports",
        "correlate_threats",
    ):
        monkeypatch.setattr(
            pipeline,
            name,
            unexpected_nmap_detection,
        )

    windows_event = object()
    windows_finding = object()

    monkeypatch.setattr(
        pipeline,
        "parse_windows_events",
        lambda _path: [windows_event],
    )

    def detect_windows(events, **kwargs):
        assert events == [windows_event]
        return [windows_finding]

    monkeypatch.setattr(
        pipeline,
        "detect_windows_events",
        detect_windows,
    )

    firewall_event = object()
    firewall_finding = object()

    monkeypatch.setattr(
        pipeline,
        "parse_firewall_log",
        lambda _path, *, diagnostics=None: [firewall_event],
    )

    def detect_firewall(events, **kwargs):
        assert events == [firewall_event]
        return [firewall_finding]

    monkeypatch.setattr(
        pipeline,
        "detect_firewall_events",
        detect_firewall,
    )

    # Healthy Web source.
    web_event = object()
    web_finding = object()

    monkeypatch.setattr(
        pipeline,
        "parse_web_log",
        lambda _path: [web_event],
    )

    def detect_web(events):
        assert events == [web_event]
        return [web_finding]

    monkeypatch.setattr(
        pipeline,
        "detect_web_attacks",
        detect_web,
    )

    pipeline_args = dict(
        nmap_file="restricted",
        windows_events_file="healthy",
        firewall_file="healthy",
        web_log_file="healthy",
        whitelist_file="unused",
        critical_ports_file="unused",
    )

    with pytest.raises(exception_type):
        pipeline.run_traditional_detection_pipeline(
            **pipeline_args,
        )

    source_failures = []

    result = pipeline.run_traditional_detection_pipeline(
        **pipeline_args,
        source_failures=source_failures,
    )

    assert result.nmap_findings == []

    assert result.windows_findings == [windows_finding]
    assert result.firewall_events == [firewall_event]
    assert result.firewall_findings == [firewall_finding]
    assert result.web_findings == [web_finding]

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("nmap", expected_reason),
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
def test_traditional_pipeline_isolates_web_log_source_failure(
    monkeypatch,
    exception_type,
    expected_reason,
):
    import src.application.traditional_detection_pipeline as pipeline

    monkeypatch.setattr(
        pipeline,
        "parse_nmap_xml",
        lambda _path: [],
    )
    monkeypatch.setattr(
        pipeline,
        "detect_unknown_ips",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        pipeline,
        "detect_critical_ports",
        lambda *args, **kwargs: [],
    )
    monkeypatch.setattr(
        pipeline,
        "correlate_threats",
        lambda *args, **kwargs: [],
    )

    windows_event = object()
    windows_finding = object()

    monkeypatch.setattr(
        pipeline,
        "parse_windows_events",
        lambda _path: [windows_event],
    )

    def detect_windows(events, **kwargs):
        assert events == [windows_event]
        return [windows_finding]

    monkeypatch.setattr(
        pipeline,
        "detect_windows_events",
        detect_windows,
    )

    firewall_event = object()
    firewall_finding = object()

    monkeypatch.setattr(
        pipeline,
        "parse_firewall_log",
        lambda _path, *, diagnostics=None: [firewall_event],
    )

    def detect_firewall(events, **kwargs):
        assert events == [firewall_event]
        return [firewall_finding]

    monkeypatch.setattr(
        pipeline,
        "detect_firewall_events",
        detect_firewall,
    )

    def failed_web_log(_path):
        raise exception_type(
            "sensitive=/private/internal/web.log"
        )

    monkeypatch.setattr(
        pipeline,
        "parse_web_log",
        failed_web_log,
    )

    def unexpected_web_detection(*args, **kwargs):
        raise AssertionError(
            "Web detection ran without Web telemetry"
        )

    monkeypatch.setattr(
        pipeline,
        "detect_web_attacks",
        unexpected_web_detection,
    )

    pipeline_args = dict(
        nmap_file="healthy",
        windows_events_file="healthy",
        firewall_file="healthy",
        web_log_file="restricted",
        whitelist_file="unused",
        critical_ports_file="unused",
    )

    with pytest.raises(exception_type):
        pipeline.run_traditional_detection_pipeline(
            **pipeline_args,
        )

    source_failures = []

    result = pipeline.run_traditional_detection_pipeline(
        **pipeline_args,
        source_failures=source_failures,
    )

    assert result.web_findings == []

    assert result.nmap_findings == []
    assert result.windows_findings == [windows_finding]
    assert result.firewall_events == [firewall_event]
    assert result.firewall_findings == [firewall_finding]

    assert [
        (failure.source, failure.reason)
        for failure in source_failures
    ] == [
        ("web_log", expected_reason),
    ]

    assert "sensitive=" not in repr(source_failures)
    assert "/private/internal" not in repr(source_failures)


@pytest.mark.parametrize(
    "parser_name",
    [
        "parse_nmap_xml",
        "parse_windows_events",
        "parse_firewall_log",
        "parse_web_log",
    ],
)
@pytest.mark.parametrize(
    "exception_type",
    [ValueError, TypeError],
    ids=["value_error", "type_error"],
)
def test_traditional_pipeline_does_not_suppress_programming_errors(
    monkeypatch,
    parser_name,
    exception_type,
):
    import src.application.traditional_detection_pipeline as pipeline

    for name in (
        "parse_nmap_xml",
        "parse_windows_events",
        "parse_firewall_log",
        "parse_web_log",
    ):
        monkeypatch.setattr(
            pipeline,
            name,
            lambda *args, **kwargs: [],
        )

    for name in (
        "detect_unknown_ips",
        "detect_critical_ports",
        "correlate_threats",
        "detect_windows_events",
        "detect_firewall_events",
        "detect_web_attacks",
    ):
        monkeypatch.setattr(
            pipeline,
            name,
            lambda *args, **kwargs: [],
        )

    def broken_parser(*args, **kwargs):
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
        pipeline.run_traditional_detection_pipeline(
            nmap_file="unused",
            windows_events_file="unused",
            firewall_file="unused",
            web_log_file="unused",
            whitelist_file="unused",
            critical_ports_file="unused",
            source_failures=source_failures,
        )

    assert source_failures == []
