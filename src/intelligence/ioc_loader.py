import json
from pathlib import Path

from src.models.ioc import IOC


IOC_DATABASE = Path("data/ioc_database.json")


def load_database() -> dict:
    """
    Load IOC database from JSON file.
    """

    with open(IOC_DATABASE, "r", encoding="utf-8") as file:
        return json.load(file)


def get_iocs() -> list[IOC]:
    """
    Return all IOC objects.
    """

    database = load_database()

    iocs = []

    mapping = {
        "ips": "ip",
        "domains": "domain",
        "urls": "url",
        "hashes": "hash",
    }

    for section, ioc_type in mapping.items():

        for item in database.get(section, []):

            iocs.append(
                IOC(
                    value=item["value"],
                    ioc_type=ioc_type,
                    source="Local IOC Database",
                    confidence=item.get("confidence", "medium"),
                    description=item.get("description", "")
                )
            )

    return iocs