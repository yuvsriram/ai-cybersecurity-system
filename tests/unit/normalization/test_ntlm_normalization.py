from cybersec.ingestion.parsers.windows_xml import (
    parse_xml_event,
)
from cybersec.normalization.ntlm import (
    normalize_ntlm_event,
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


def test_normalize_ntlm_8004() -> None:
    record = parse_xml_event(SAMPLE_EVENT)

    event = normalize_ntlm_event(
        record,
        dataset_name="ntlm_test",
    )

    assert event is not None

    assert event.event_code == "8004"
    assert event.category == "authentication"
    assert event.action == "ntlm_authentication"

    assert event.user_name == "backup"
    assert event.user_domain is None

    assert event.source_host == "WIN-CLIENT"
    assert event.destination_host == "VICTIM_PC"

    assert (
        event.host_name
        == "attack_dc.attack_range.lan"
    )

    assert event.source_record_id == "2728229667"


def test_non_8004_event_is_ignored() -> None:
    raw = SAMPLE_EVENT.replace(
        "<EventID>8004</EventID>",
        "<EventID>8005</EventID>",
    )

    record = parse_xml_event(raw)

    assert (
        normalize_ntlm_event(
            record,
            dataset_name="ntlm_test",
        )
        is None
    )