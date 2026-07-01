from dataclasses import dataclass


@dataclass
class IOC:
    """
    Indicator of Compromise (IOC).
    """

    value: str
    ioc_type: str
    source: str
    confidence: str = "medium"
    description: str = ""
