"""CORE-07 bounded quarantine contract tests."""

import pytest

from src.parsers.quarantine_buffer import QuarantineBuffer


def test_quarantine_buffer_limits_retention_and_counts_drops():
    quarantine = QuarantineBuffer(
        max_records=2,
        max_record_bytes=128,
    )

    quarantine.capture(
        source="firewall",
        line_number=2,
        reason_code="too_few_fields",
        raw_record="PRIVATE_FIREWALL_TOKEN_A",
    )

    quarantine.capture(
        source="firewall",
        line_number=4,
        reason_code="invalid_port",
        raw_record="PRIVATE_FIREWALL_TOKEN_B",
    )

    quarantine.capture(
        source="firewall",
        line_number=6,
        reason_code="invalid_format",
        raw_record="PRIVATE_FIREWALL_TOKEN_C",
    )

    assert len(quarantine.records) == 2
    assert quarantine.dropped == 1

    assert [
        (
            record.source,
            record.line_number,
            record.reason_code,
            record.raw_record,
        )
        for record in quarantine.records
    ] == [
        (
            "firewall",
            2,
            "too_few_fields",
            "PRIVATE_FIREWALL_TOKEN_A",
        ),
        (
            "firewall",
            4,
            "invalid_port",
            "PRIVATE_FIREWALL_TOKEN_B",
        ),
    ]

    assert all(
        record.line_number != 6
        for record in quarantine.records
    )

    representation = repr(quarantine)

    assert "PRIVATE_FIREWALL_TOKEN_A" not in representation
    assert "PRIVATE_FIREWALL_TOKEN_B" not in representation
    assert "PRIVATE_FIREWALL_TOKEN_C" not in representation


def test_quarantine_with_zero_capacity_drops_every_record():
    quarantine = QuarantineBuffer(
        max_records=0,
        max_record_bytes=128,
    )

    retained = quarantine.capture(
        source="firewall",
        line_number=1,
        reason_code="too_few_fields",
        raw_record="PRIVATE_FIREWALL_DATA",
    )

    assert retained is False
    assert quarantine.records == []
    assert quarantine.dropped == 1


def test_quarantine_enforces_utf8_byte_limit():
    quarantine = QuarantineBuffer(
        max_records=2,
        max_record_bytes=4,
    )

    assert quarantine.capture(
        source="nginx",
        line_number=1,
        reason_code="invalid_json",
        raw_record="éé",
    ) is True

    assert quarantine.capture(
        source="nginx",
        line_number=2,
        reason_code="invalid_json",
        raw_record="ééé",
    ) is False

    assert quarantine.capture(
        source="nginx",
        line_number=3,
        reason_code="invalid_json",
        raw_record="abcd",
    ) is True

    assert len(quarantine.records) == 2
    assert quarantine.dropped == 1


def test_quarantine_rejects_unencodable_unicode():
    quarantine = QuarantineBuffer(
        max_records=2,
        max_record_bytes=16,
    )

    retained = quarantine.capture(
        source="waf_cdn",
        line_number=1,
        reason_code="invalid_json",
        raw_record="\ud800",
    )

    assert retained is False
    assert quarantine.records == []
    assert quarantine.dropped == 1


@pytest.mark.parametrize(
    ("max_records", "max_record_bytes"),
    [
        (-1, 128),
        (2, -1),
        (True, 128),
        (2, False),
    ],
)
def test_quarantine_rejects_invalid_limits(
    max_records,
    max_record_bytes,
):
    with pytest.raises(ValueError):
        QuarantineBuffer(
            max_records=max_records,
            max_record_bytes=max_record_bytes,
        )


def test_quarantine_buffers_are_independent_per_source():
    firewall_quarantine = QuarantineBuffer(
        max_records=1,
        max_record_bytes=128,
    )

    nginx_quarantine = QuarantineBuffer(
        max_records=1,
        max_record_bytes=128,
    )

    assert firewall_quarantine.capture(
        source="firewall",
        line_number=1,
        reason_code="too_few_fields",
        raw_record="PRIVATE_FIREWALL_A",
    ) is True

    assert firewall_quarantine.capture(
        source="firewall",
        line_number=2,
        reason_code="invalid_port",
        raw_record="PRIVATE_FIREWALL_B",
    ) is False

    assert nginx_quarantine.capture(
        source="nginx",
        line_number=1,
        reason_code="invalid_json",
        raw_record="PRIVATE_NGINX_A",
    ) is True

    assert len(firewall_quarantine.records) == 1
    assert firewall_quarantine.dropped == 1

    assert len(nginx_quarantine.records) == 1
    assert nginx_quarantine.dropped == 0

    assert (
        firewall_quarantine.records[0].source
        == "firewall"
    )
    assert (
        nginx_quarantine.records[0].source
        == "nginx"
    )
