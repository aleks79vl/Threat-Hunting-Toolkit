from pathlib import Path

from src.detection.web.web_baseline_detector import (
    load_web_security_baseline,
)
from src.detection.web.web_infrastructure_pipeline import (
    run_web_infrastructure_detection_pipeline,
)
from src.parsers.apache_access_log_parser import (
    parse_apache_access_log,
    parse_apache_vhost_access_log,
)
from src.parsers.apache_error_log_parser import (
    parse_apache_error_log,
)
from src.parsers.api_gateway_log_parser import (
    parse_api_gateway_log,
)
from src.parsers.haproxy_log_parser import (
    parse_haproxy_http_log,
)
from src.parsers.nginx_error_log_parser import (
    parse_nginx_error_log,
)
from src.parsers.nginx_json_log_parser import (
    parse_nginx_json_log,
)
from src.parsers.waf_cdn_log_parser import (
    parse_waf_cdn_log,
)


WEB_DATA_DIR = Path("data/raw/web")
WEB_BASELINE_FILE = Path("config/web_security_baseline.json")


def test_web_infrastructure_fixture_pipeline():
    events = (
        parse_apache_access_log(
            WEB_DATA_DIR / "apache_access.log"
        )
        + parse_apache_vhost_access_log(
            WEB_DATA_DIR / "apache_vhost_access.log"
        )
        + parse_apache_error_log(
            WEB_DATA_DIR / "apache_error.log"
        )
        + parse_nginx_json_log(
            WEB_DATA_DIR / "nginx_access.jsonl"
        )
        + parse_nginx_error_log(
            WEB_DATA_DIR / "nginx_error.log"
        )
        + parse_api_gateway_log(
            WEB_DATA_DIR / "api_gateway_access.jsonl"
        )
        + parse_haproxy_http_log(
            WEB_DATA_DIR / "haproxy_http.log"
        )
        + parse_waf_cdn_log(
            WEB_DATA_DIR / "waf_cdn_events.jsonl"
        )
    )

    baseline = load_web_security_baseline(
        WEB_BASELINE_FILE
    )

    result = run_web_infrastructure_detection_pipeline(
        events,
        web_security_baseline=baseline,
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

    finding_sources = {
        finding.source
        for finding in result.findings
    }

    assert {
        "Nginx Reverse Proxy Detector",
        "Nginx Upstream Error Detector",
        "HAProxy Load Balancer Detector",
    } <= finding_sources


def test_nginx_json_headers_trigger_header_manipulation_detection(tmp_path):
    log_file = tmp_path / "nginx_header_attack.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"host":"example.com",'
        '"request_headers":{"X-Original-URL":"/admin/users"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Potential Header-Based Route Override" in finding_titles


def test_nginx_json_headers_trigger_http_request_smuggling_detection(
    tmp_path,
):
    log_file = tmp_path / "nginx_smuggling.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"POST",'
        '"request_uri":"/submit",'
        '"status":200,'
        '"host":"example.com",'
        '"request_headers":{'
        '"Content-Length":"10",'
        '"Transfer-Encoding":"chunked"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Ambiguous HTTP Request Framing Detected" in finding_titles


def test_nginx_json_headers_trigger_cache_poisoning_detection(tmp_path):
    log_file = tmp_path / "nginx_cache_poisoning.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/news",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"X-Forwarded-Host":"attacker.example"},'
        '"response_headers":{'
        '"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )


    events = parse_nginx_json_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Potential Web Cache Poisoning via Forwarded Host"
        in finding_titles
    )


def test_nginx_json_headers_trigger_backend_exposure_detection(tmp_path):
    log_file = tmp_path / "nginx_backend_exposure.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/redirect",'
        '"status":302,'
        '"host":"api.example.com",'
        '"response_headers":{'
        '"Location":"http://10.0.0.5/internal"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Private Backend Address Exposed in Response"
        in finding_titles
    )


def test_nginx_json_safe_forwarded_host_does_not_trigger_cache_poisoning(
    tmp_path,
):
    log_file = tmp_path / "nginx_safe_cache.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/news",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"X-Forwarded-Host":"api.example.com"},'
        '"response_headers":{'
        '"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )


    events = parse_nginx_json_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Potential Web Cache Poisoning via Forwarded Host"
        not in finding_titles
    )


def test_nginx_json_normal_content_length_does_not_trigger_smuggling(
    tmp_path,
):
    log_file = tmp_path / "nginx_normal_post.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"POST",'
        '"request_uri":"/submit",'
        '"status":200,'
        '"host":"example.com",'
        '"request_headers":{'
        '"Content-Length":"10",'
        '"Content-Type":"application/json"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Ambiguous HTTP Request Framing Detected" not in finding_titles


def test_nginx_json_normal_headers_do_not_trigger_header_manipulation(
    tmp_path,
):
    log_file = tmp_path / "nginx_normal_headers.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/profile",'
        '"status":200,'
        '"host":"example.com",'
        '"request_headers":{'
        '"Accept":"application/json",'
        '"X-Request-ID":"request-123"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Potential Header-Based Route Override" not in finding_titles


def test_nginx_json_public_redirect_does_not_trigger_backend_exposure(
    tmp_path,
):
    log_file = tmp_path / "nginx_public_redirect.jsonl"

    log_file.write_text(
        '{"time":"2026-10-21T10:00:00Z",'
        '"remote_addr":"192.0.2.10",'
        '"request_method":"GET",'
        '"request_uri":"/redirect",'
        '"status":302,'
        '"host":"api.example.com",'
        '"response_headers":{'
        '"Location":"https://www.example.org/login"}}\n',
        encoding="utf-8",
    )

    events = parse_nginx_json_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Private Backend Address Exposed in Response"
        not in finding_titles
    )


def test_waf_cdn_json_headers_trigger_header_manipulation_detection(
    tmp_path,
):
    log_file = tmp_path / "waf_header_attack.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"provider":"cloudflare",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/profile",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"action":"allow",'
        '"request_headers":{'
        '"X-Original-URL":"/admin/users"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Potential Header-Based Route Override"
        in finding_titles
    )


def test_waf_cdn_json_headers_trigger_http_request_smuggling_detection(
    tmp_path,
):
    log_file = tmp_path / "waf_smuggling.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"provider":"cloudflare",'
        '"client_ip":"192.0.2.10",'
        '"method":"POST",'
        '"path":"/submit",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"action":"allow",'
        '"request_headers":{'
        '"Content-Length":"10",'
        '"Transfer-Encoding":"chunked"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Ambiguous HTTP Request Framing Detected" in finding_titles


def test_waf_cdn_json_headers_trigger_cache_poisoning_detection(
    tmp_path,
):
    log_file = tmp_path / "waf_cache_poisoning.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"provider":"cloudflare",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/news",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"action":"allow",'
        '"request_headers":{'
        '"X-Forwarded-Host":"attacker.example"},'
        '"response_headers":{'
        '"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Potential Web Cache Poisoning via Forwarded Host"
        in finding_titles
    )


def test_waf_cdn_json_headers_trigger_backend_exposure_detection(
    tmp_path,
):
    log_file = tmp_path / "waf_backend_exposure.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"provider":"cloudflare",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/redirect",'
        '"status_code":302,'
        '"host":"api.example.com",'
        '"action":"allow",'
        '"response_headers":{'
        '"Location":"http://10.0.0.5/internal"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Private Backend Address Exposed in Response"
        in finding_titles
    )


def test_waf_cdn_json_safe_forwarded_host_does_not_trigger_cache_poisoning(
    tmp_path,
):
    log_file = tmp_path / "waf_safe_cache.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"provider":"cloudflare",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/news",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"action":"allow",'
        '"request_headers":{'
        '"X-Forwarded-Host":"api.example.com"},'
        '"response_headers":{'
        '"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Potential Web Cache Poisoning via Forwarded Host"
        not in finding_titles
    )


def test_waf_cdn_json_normal_content_length_does_not_trigger_smuggling(
    tmp_path,
):
    log_file = tmp_path / "waf_normal_post.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"provider":"cloudflare",'
        '"client_ip":"192.0.2.10",'
        '"method":"POST",'
        '"path":"/submit",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"action":"allow",'
        '"request_headers":{'
        '"Content-Length":"10",'
        '"Content-Type":"application/json"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Ambiguous HTTP Request Framing Detected" not in finding_titles


def test_waf_cdn_json_normal_headers_do_not_trigger_header_manipulation(
    tmp_path,
):
    log_file = tmp_path / "waf_normal_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"provider":"cloudflare",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/profile",'
        '"status_code":200,'
        '"host":"api.example.com",'
        '"action":"allow",'
        '"request_headers":{'
        '"Accept":"application/json",'
        '"X-Request-ID":"request-123"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Potential Header-Based Route Override" not in finding_titles


def test_waf_cdn_json_public_redirect_does_not_trigger_backend_exposure(
    tmp_path,
):
    log_file = tmp_path / "waf_public_redirect.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-21T10:00:00Z",'
        '"provider":"cloudflare",'
        '"client_ip":"192.0.2.10",'
        '"method":"GET",'
        '"path":"/redirect",'
        '"status_code":302,'
        '"host":"api.example.com",'
        '"action":"allow",'
        '"response_headers":{'
        '"Location":"https://www.example.org/login"}}\n',
        encoding="utf-8",
    )

    events = parse_waf_cdn_log(log_file)
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Private Backend Address Exposed in Response"
        not in finding_titles
    )


def test_api_gateway_json_headers_trigger_header_manipulation_detection(
    tmp_path,
):
    log_file = tmp_path / "api_gateway_header_attack.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/profile",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"X-Original-URL":"/admin/users"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Potential Header-Based Route Override" in finding_titles


def test_api_gateway_json_headers_trigger_http_request_smuggling_detection(
    tmp_path,
):
    log_file = tmp_path / "api_gateway_smuggling.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"POST",'
        '"path":"/submit",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"Content-Length":"10",'
        '"Transfer-Encoding":"chunked"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Ambiguous HTTP Request Framing Detected" in finding_titles


def test_api_gateway_json_headers_trigger_cache_poisoning_detection(
    tmp_path,
):
    log_file = tmp_path / "api_gateway_cache_poisoning.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/news",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"X-Forwarded-Host":"attacker.example"},'
        '"response_headers":{'
        '"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Potential Web Cache Poisoning via Forwarded Host"
        in finding_titles
    )


def test_api_gateway_json_headers_trigger_backend_exposure_detection(
    tmp_path,
):
    log_file = tmp_path / "api_gateway_backend_exposure.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/redirect",'
        '"status":302,'
        '"host":"api.example.com",'
        '"response_headers":{'
        '"Location":"http://10.0.0.5/internal"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Private Backend Address Exposed in Response"
        in finding_titles
    )


def test_api_gateway_json_safe_forwarded_host_does_not_trigger_cache_poisoning(
    tmp_path,
):
    log_file = tmp_path / "api_gateway_safe_cache.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/news",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"X-Forwarded-Host":"api.example.com"},'
        '"response_headers":{'
        '"Cache-Control":"public, max-age=300"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Potential Web Cache Poisoning via Forwarded Host"
        not in finding_titles
    )


def test_api_gateway_json_normal_content_length_does_not_trigger_smuggling(
    tmp_path,
):
    log_file = tmp_path / "api_gateway_normal_post.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"POST",'
        '"path":"/submit",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"Content-Length":"10",'
        '"Content-Type":"application/json"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Ambiguous HTTP Request Framing Detected" not in finding_titles


def test_api_gateway_json_normal_headers_do_not_trigger_header_manipulation(
    tmp_path,
):
    log_file = tmp_path / "api_gateway_normal_headers.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/profile",'
        '"status":200,'
        '"host":"api.example.com",'
        '"request_headers":{'
        '"Accept":"application/json",'
        '"X-Request-ID":"req-12345"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert "Potential Header-Based Route Override" not in finding_titles


def test_api_gateway_json_public_redirect_does_not_trigger_backend_exposure(
    tmp_path,
):
    log_file = tmp_path / "api_gateway_safe_redirect.jsonl"

    log_file.write_text(
        '{"timestamp":"2026-10-22T10:00:00Z",'
        '"client_ip":"192.0.2.10",'
        '"http_method":"GET",'
        '"path":"/redirect",'
        '"status":302,'
        '"host":"api.example.com",'
        '"response_headers":{'
        '"Location":"https://www.example.com/login"}}\n',
        encoding="utf-8",
    )

    events = parse_api_gateway_log(str(log_file))
    result = run_web_infrastructure_detection_pipeline(events)

    finding_titles = {
        finding.title
        for finding in result.findings
    }

    assert (
        "Private Backend Address Exposed in Response"
        not in finding_titles
    )
