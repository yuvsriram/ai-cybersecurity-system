from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from pathlib import Path

from cybersec.ingestion.parsers.windows_xml import parse_file


DATASET_PATH = Path(
    "data/raw/splunk/ntlm_bruteforce.log"
)


def main() -> None:
    records = parse_file(DATASET_PATH)

    groups = defaultdict(list)

    for record in records:
        key = (
            record.channel,
            record.computer,
            record.record_id,
        )

        groups[key].append(record)

    duplicate_groups = {
        key: values
        for key, values in groups.items()
        if len(values) > 1
    }

    duplicate_excess = sum(
        len(values) - 1
        for values in duplicate_groups.values()
    )

    print(f"Total records: {len(records)}")
    print(f"Unique identities: {len(groups)}")
    print(
        f"Duplicate identity groups: "
        f"{len(duplicate_groups)}"
    )
    print(
        f"Duplicate records beyond first: "
        f"{duplicate_excess}"
    )
    print()

    for key, values in sorted(
        duplicate_groups.items(),
        key=lambda item: str(item[0]),
    ):
        hashes = {
            sha256(
                record.raw_xml.encode("utf-8")
            ).hexdigest()
            for record in values
        }

        print(
            f"identity={key} "
            f"count={len(values)} "
            f"distinct_payloads={len(hashes)}"
        )


if __name__ == "__main__":
    main()