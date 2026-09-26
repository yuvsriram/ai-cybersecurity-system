from cybersec.ingestion.parsers.splunk_kv import parse_records
from cybersec.normalization.windows_security import (
    normalize_windows_security_event,
)


def test_normalize_account_lockout_event() -> None:
    raw_log = (
        "11/09/2020 12:05:22 PM\n"
        "LogName=Security\n"
        "SourceName=Microsoft Windows security auditing.\n"
        "EventCode=4740\n"
        "EventType=0\n"
        "Type=Information\n"
        "ComputerName=win-dc-259.attackrange.local\n"
        "TaskCategory=User Account Management\n"
        "OpCode=Info\n"
        "RecordNumber=232850\n"
        "Keywords=Audit Success\n"
        "Message=A user account was locked out.\n"
        "\n"
        "Subject:\n"
        "    Security ID: NT AUTHORITY\\SYSTEM\n"
        "    Account Name: WIN-DC-259$\n"
        "    Account Domain: ATTACKRANGE\n"
        "    Logon ID: 0x3E7\n"
        "\n"
        "Account That Was Locked Out:\n"
        "    Security ID: ATTACKRANGE\\paba\n"
        "    Account Name: paba\n"
        "\n"
        "Additional Information:\n"
        "    Caller Computer Name: ATTACK-PC\n"
    )

    source_record = list(
        parse_records(raw_log.splitlines(keepends=True))
    )[0]

    event = normalize_windows_security_event(source_record)

    assert event is not None
    assert event.event_code == "4740"
    assert event.category == "identity"
    assert event.action == "account_lockout"
    assert event.outcome == "success"

    assert event.user_name == "paba"
    assert event.user_domain == "ATTACKRANGE"

    assert event.source_host == "ATTACK-PC"
    assert event.host_name == "win-dc-259.attackrange.local"

    assert event.attributes["RecordNumber"] == "232850"


def test_normalize_failed_logon_event() -> None:
    raw_log = (
        "11/09/2020 12:05:22 PM\n"
        "LogName=Security\n"
        "SourceName=Microsoft Windows security auditing.\n"
        "EventCode=4625\n"
        "EventType=0\n"
        "Type=Information\n"
        "ComputerName=win-dc-259.attackrange.local\n"
        "TaskCategory=Logon\n"
        "Keywords=Audit Failure\n"
        "Message=An account failed to log on.\n"
        "\n"
        "Account For Which Logon Failed:\n"
        "    Security ID: NULL SID\n"
        "    Account Name: alice\n"
        "    Account Domain: ATTACKRANGE\n"
        "\n"
        "Network Information:\n"
        "    Workstation Name: CLIENT-01\n"
        "    Source Network Address: 10.10.20.15\n"
        "    Source Port: 55123\n"
    )

    source_record = list(
        parse_records(raw_log.splitlines(keepends=True))
    )[0]

    event = normalize_windows_security_event(source_record)

    assert event is not None
    assert event.event_code == "4625"
    assert event.category == "authentication"
    assert event.action == "logon"
    assert event.outcome == "failure"

    assert event.user_name == "alice"
    assert event.user_domain == "ATTACKRANGE"

    assert event.source_host == "CLIENT-01"
    assert event.source_ip == "10.10.20.15"


def test_unsupported_windows_event_returns_none() -> None:
    raw_log = (
        "11/09/2020 12:05:22 PM\n"
        "LogName=Security\n"
        "EventCode=4688\n"
        "ComputerName=host-01\n"
        "Message=A new process has been created.\n"
    )

    source_record = list(
        parse_records(raw_log.splitlines(keepends=True))
    )[0]

    event = normalize_windows_security_event(source_record)

    assert event is None

def test_empty_domain_does_not_capture_next_section() -> None:
    raw_log = (
        "11/09/2020 12:09:59 PM\n"
        "LogName=Security\n"
        "SourceName=Microsoft Windows security auditing.\n"
        "EventCode=4625\n"
        "ComputerName=win-host-8.attackrange.local\n"
        "RecordNumber=230893\n"
        "Message=An account failed to log on.\n"
        "\n"
        "Account For Which Logon Failed:\n"
        "    Security ID: NULL SID\n"
        "    Account Name: paba\n"
        "    Account Domain:\n"
        "\n"
        "Failure Information:\n"
        "    Failure Reason: Unknown user name or bad password.\n"
        "\n"
        "Network Information:\n"
        "    Workstation Name: -\n"
        "    Source Network Address: 95.90.199.65\n"
    )

    source_record = list(
        parse_records(raw_log.splitlines(keepends=True))
    )[0]

    event = normalize_windows_security_event(source_record)

    assert event is not None
    assert event.user_name == "paba"
    assert event.user_domain is None
    assert event.source_ip == "95.90.199.65"