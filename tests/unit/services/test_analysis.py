from __future__ import annotations

from datetime import (
    datetime,
    timedelta,
)


from cybersec.services.analysis import (
    analyze_security_logs,
    build_severity_summary,
)


def _failed_logon_record(
    *,
    occurred_at: datetime,
    record_number: int,
    user_name: str = "alice",
    source_ip: str = "10.0.0.50",
) -> str:
    timestamp = occurred_at.strftime(
        "%m/%d/%Y %I:%M:%S %p"
    )

    return (
        f"{timestamp}\n"
        "EventCode=4625\n"
        "SourceName=Microsoft-Windows-"
        "Security-Auditing\n"
        "LogName=Security\n"
        "ComputerName=SERVER01\n"
        f"RecordNumber={record_number}\n"
        "Message=An account failed "
        "to log on.\n"
        "Account For Which Logon Failed:\n"
        "    Security ID: NULL SID\n"
        f"    Account Name: {user_name}\n"
        "    Account Domain: CORP\n"
        "Network Information:\n"
        "    Workstation Name: CLIENT01\n"
        f"    Source Network Address: "
        f"{source_ip}\n"
        "\n"
    )


def _lockout_record(
    *,
    occurred_at: datetime,
    record_number: int,
) -> str:
    timestamp = occurred_at.strftime(
        "%m/%d/%Y %I:%M:%S %p"
    )

    return (
        f"{timestamp}\n"
        "EventCode=4740\n"
        "SourceName=Microsoft-Windows-"
        "Security-Auditing\n"
        "LogName=Security\n"
        "ComputerName=DC01\n"
        f"RecordNumber={record_number}\n"
        "Message=A user account "
        "was locked out.\n"
        "Account That Was Locked Out:\n"
        "    Security ID: CORP\\alice\n"
        "    Account Name: alice\n"
        "Additional Information:\n"
        "    Caller Computer Name: "
        "CLIENT01\n"
        "\n"
    )


def _ntlm_event(
    *,
    occurred_at: datetime,
    record_number: int,
    user_name: str,
    workstation: str = "ATTACKER01",
) -> str:
    timestamp = occurred_at.isoformat(
        timespec="microseconds"
    ).replace(
        "+00:00",
        "Z",
    )

    return (
        '<Event xmlns="http://schemas.'
        'microsoft.com/win/2004/08/'
        'events/event">'
        "<System>"
        '<Provider Name="Microsoft-'
        'Windows-NTLM"/>'
        "<EventID>8004</EventID>"
        f'<TimeCreated SystemTime="'
        f'{timestamp}"/>'
        f"<EventRecordID>"
        f"{record_number}"
        f"</EventRecordID>"
        "<Channel>Microsoft-Windows-"
        "NTLM/Operational</Channel>"
        "<Computer>DC01</Computer>"
        '<Security UserID="'
        'S-1-5-18"/>'
        "</System>"
        "<EventData>"
        '<Data Name="DomainName">'
        "CORP"
        "</Data>"
        '<Data Name="UserName">'
        f"{user_name}"
        "</Data>"
        '<Data Name="WorkstationName">'
        f"{workstation}"
        "</Data>"
        '<Data Name="SChannelName">'
        "DC01"
        "</Data>"
        '<Data Name="SChannelType">'
        "2"
        "</Data>"
        "</EventData>"
        "</Event>"
    )


def test_analysis_detects_failed_logon_burst(
) -> None:
    start = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
    )

    content = "".join(
        _failed_logon_record(
            occurred_at=(
                start
                + timedelta(
                    seconds=index * 30
                )
            ),
            record_number=(
                1000 + index
            ),
        )
        for index in range(5)
    )

    result = analyze_security_logs(
        format=(
            "splunk_windows_security"
        ),
        content=content,
    )

    assert result.parsed_records == 5
    assert result.normalized_events == 5
    assert result.unsupported_records == 0

    assert len(result.alerts) == 1

    alert = result.alerts[0]

    assert alert.rule_id == "AUTH-002"
    assert alert.severity == "high"

    assert (
        result.overall_severity
        == "high"
    )


def test_analysis_detects_account_lockout(
) -> None:
    content = _lockout_record(
        occurred_at=datetime(
            2026,
            1,
            1,
            12,
            0,
            0,
        ),
        record_number=2000,
    )

    result = analyze_security_logs(
        format=(
            "splunk_windows_security"
        ),
        content=content,
    )

    assert result.parsed_records == 1
    assert result.normalized_events == 1

    assert len(result.alerts) == 1

    alert = result.alerts[0]

    assert alert.rule_id == "AUTH-001"
    assert alert.severity == "medium"

    assert (
        result.overall_severity
        == "medium"
    )


def test_analysis_detects_ntlm_password_spray(
) -> None:
    from datetime import timezone

    start = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
        tzinfo=timezone.utc,
    )

    content = "\n".join(
        _ntlm_event(
            occurred_at=(
                start
                + timedelta(
                    seconds=index * 5
                )
            ),
            record_number=(
                3000 + index
            ),
            user_name=(
                f"user{index:02d}"
            ),
        )
        for index in range(20)
    )

    result = analyze_security_logs(
        format="windows_ntlm_xml",
        content=content,
    )

    assert result.parsed_records == 20
    assert result.normalized_events == 20

    assert any(
        alert.rule_id == "AUTH-003"
        for alert in result.alerts
    )

    assert (
        result.overall_severity
        == "high"
    )


def test_analysis_clean_input_has_no_alerts(
) -> None:
    content = (
        "01/01/2026 12:00:00 PM\n"
        "EventCode=4688\n"
        "SourceName=Microsoft-Windows-"
        "Security-Auditing\n"
        "LogName=Security\n"
        "ComputerName=SERVER01\n"
        "RecordNumber=4000\n"
        "Message=A new process "
        "has been created.\n"
    )

    result = analyze_security_logs(
        format=(
            "splunk_windows_security"
        ),
        content=content,
    )

    assert result.parsed_records == 1
    assert result.normalized_events == 0
    assert result.unsupported_records == 1

    assert result.alerts == ()
    assert (
        result.overall_severity
        == "none"
    )


def test_severity_summary_counts_alerts(
) -> None:
    start = datetime(
        2026,
        1,
        1,
        12,
        0,
        0,
    )

    content = (
        _lockout_record(
            occurred_at=start,
            record_number=5000,
        )
        + "".join(
            _failed_logon_record(
                occurred_at=(
                    start
                    + timedelta(
                        seconds=(
                            30
                            + index * 30
                        )
                    )
                ),
                record_number=(
                    5100 + index
                ),
            )
            for index in range(5)
        )
    )

    result = analyze_security_logs(
        format=(
            "splunk_windows_security"
        ),
        content=content,
    )

    summary = build_severity_summary(
        result.alerts
    )

    assert summary == {
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
    }