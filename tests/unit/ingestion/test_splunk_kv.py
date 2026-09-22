import pytest

from cybersec.ingestion.parsers.splunk_kv import parse_records


def test_parse_records_splits_events_on_timestamp() -> None:
    raw_log = (
        "11/09/2020 12:05:22 PM\r\n"
        "LogName=Security\r\n"
        "SourceName=Microsoft Windows security auditing.\r\n"
        "EventCode=4740\r\n"
        "ComputerName=win-dc-259.attackrange.local\r\n"
        "Message=A user account was locked out.\r\n"
        "\r\n"
        "Subject:\r\n"
        "    Account Name: WIN-DC-259$\r\n"
        "\r\n"
        "11/09/2020 12:05:22 PM\r\n"
        "LogName=Security\r\n"
        "SourceName=Microsoft Windows security auditing.\r\n"
        "EventCode=4625\r\n"
        "ComputerName=win-dc-259.attackrange.local\r\n"
        "Message=An account failed to log on.\r\n"
    )

    parsed = list(
        parse_records(raw_log.splitlines(keepends=True))
    )

    assert len(parsed) == 2

    assert parsed[0].timestamp == "11/09/2020 12:05:22 PM"
    assert parsed[0].fields["EventCode"] == "4740"
    assert parsed[0].fields["LogName"] == "Security"
    assert (
        parsed[0].fields["ComputerName"]
        == "win-dc-259.attackrange.local"
    )

    assert parsed[1].fields["EventCode"] == "4625"


def test_parser_preserves_message_body_in_raw_text() -> None:
    raw_log = (
        "11/09/2020 12:05:22 PM\n"
        "LogName=Security\n"
        "EventCode=4740\n"
        "Message=A user account was locked out.\n"
        "\n"
        "Account That Was Locked Out:\n"
        "    Account Name: paba\n"
    )

    parsed = list(
        parse_records(raw_log.splitlines(keepends=True))
    )

    assert len(parsed) == 1
    assert "Account Name: paba" in parsed[0].raw_text


def test_parser_rejects_content_before_first_timestamp() -> None:
    raw_log = (
        "unexpected content\n"
        "11/09/2020 12:05:22 PM\n"
        "EventCode=4740\n"
    )

    with pytest.raises(
        ValueError,
        match="before the first event timestamp",
    ):
        list(parse_records(raw_log.splitlines(keepends=True)))


def test_parser_flushes_final_record_at_end_of_file() -> None:
    raw_log = (
        "11/09/2020 12:05:22 PM\n"
        "LogName=Security\n"
        "EventCode=4740\n"
    )

    parsed = list(
        parse_records(raw_log.splitlines(keepends=True))
    )

    assert len(parsed) == 1
    assert parsed[0].fields["EventCode"] == "4740"