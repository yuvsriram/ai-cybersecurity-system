from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_PATH = ROOT / ".env"

DEMO_NAME = "demo-viewer"
DEMO_ROLE = "viewer"


def read_env(
    path: Path,
) -> tuple[list[str], dict[str, str]]:
    if not path.exists():
        raise RuntimeError(
            ".env does not exist. "
            "Create it before configuring "
            "demo access."
        )

    lines = path.read_text(
        encoding="utf-8"
    ).splitlines()

    values: dict[str, str] = {}

    for line in lines:
        stripped = line.strip()

        if (
            not stripped
            or stripped.startswith("#")
            or "=" not in line
        ):
            continue

        name, value = line.split(
            "=",
            1,
        )

        values[name.strip()] = (
            value.strip()
        )

    return lines, values


def replace_env_value(
    lines: list[str],
    name: str,
    value: str,
) -> list[str]:
    prefix = f"{name}="

    result: list[str] = []
    replaced = False

    for line in lines:
        if line.startswith(prefix):
            result.append(
                f"{name}={value}"
            )
            replaced = True
        else:
            result.append(line)

    if not replaced:
        if (
            result
            and result[-1] != ""
        ):
            result.append("")

        result.append(
            f"{name}={value}"
        )

    return result


def main() -> None:
    lines, values = read_env(
        ENV_PATH
    )

    raw_credentials = values.get(
        "CYBERSEC_API_KEYS_JSON",
        "[]",
    )

    try:
        credentials = json.loads(
            raw_credentials
        )
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "CYBERSEC_API_KEYS_JSON "
            "contains invalid JSON"
        ) from exc

    if not isinstance(
        credentials,
        list,
    ):
        raise RuntimeError(
            "CYBERSEC_API_KEYS_JSON "
            "must contain a JSON array"
        )

    raw_key = secrets.token_urlsafe(
        48
    )

    digest = hashlib.sha256(
        raw_key.encode("utf-8")
    ).hexdigest()

    filtered_credentials = [
        credential
        for credential in credentials
        if (
            isinstance(
                credential,
                dict,
            )
            and credential.get(
                "name"
            )
            != DEMO_NAME
        )
    ]

    filtered_credentials.append(
        {
            "name": DEMO_NAME,
            "role": DEMO_ROLE,
            "sha256": digest,
        }
    )

    serialized_credentials = (
        json.dumps(
            filtered_credentials,
            separators=(",", ":"),
        )
    )

    lines = replace_env_value(
        lines,
        "CYBERSEC_API_KEYS_JSON",
        serialized_credentials,
    )

    lines = replace_env_value(
        lines,
        "DEMO_API_KEY",
        raw_key,
    )

    ENV_PATH.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(
        "Demo viewer access configured."
    )

    print(
        "The raw credential was written "
        "only to the ignored .env file."
    )

    print(
        "Recreate the API and frontend "
        "containers before testing."
    )


if __name__ == "__main__":
    main()