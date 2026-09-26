from cybersec.ingestion.parsers.windows_xml import (
    parse_records,
    parse_xml_event,
)


SAMPLE_EVENT = (
    "<Event xmlns="
    "'http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System>"
    "<Provider Name='Microsoft-Windows-Security-Netlogon'/>"
    "<EventID>8004</EventID>"
    "<TimeCreated "
    "SystemTime='2024-01-18T05:04:59.727635000Z'/>"
    "<EventRecordID>2728229667</EventRecordID>"
    "<Channel>Microsoft-Windows-NTLM/Operational</Channel>"
    "<Computer>attack_dc.attack_range.lan</Computer>"
    "<Security UserID='S-1-5-18'/>"
    "</System>"
    "<EventData>"
    "<Data Name='SChannelName'>VICTIM_PC</Data>"
    "<Data Name='UserName'>backup</Data>"
    "<Data Name='DomainName'>NULL</Data>"
    "<Data Name='WorkstationName'>WIN-CLIENT</Data>"
    "<Data Name='SChannelType'>2</Data>"
    "</EventData>"
    "</Event>"
)


def test_parse_xml_event() -> None:
    record = parse_xml_event(SAMPLE_EVENT)

    assert record.event_id == "8004"
    assert record.record_id == "2728229667"

    assert (
        record.provider
        == "Microsoft-Windows-Security-Netlogon"
    )

    assert (
        record.channel
        == "Microsoft-Windows-NTLM/Operational"
    )

    assert (
        record.computer
        == "attack_dc.attack_range.lan"
    )

    assert record.event_data["UserName"] == "backup"
    assert record.event_data["SChannelName"] == "VICTIM_PC"

    assert record.occurred_at.tzinfo is not None


def test_parse_multiple_xml_records() -> None:
    records = parse_records(
        [
            SAMPLE_EVENT + "\n",
            "\n",
            SAMPLE_EVENT + "\n",
        ]
    )

    assert len(records) == 2


def test_invalid_xml_raises_value_error() -> None:
    try:
        parse_xml_event("<Event>")
    except ValueError as exc:
        assert "Invalid Windows event XML" in str(exc)
    else:
        raise AssertionError(
            "Expected ValueError"
        )