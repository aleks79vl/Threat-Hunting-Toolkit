from src.correlation.mitre_mapper import get_mitre_mapping


def test_sql_injection():
    mitre = get_mitre_mapping("SQL Injection Attempt Detected")

    assert mitre["technique"] == "T1190"
    assert mitre["tactic"] == "Initial Access"


def test_powershell():
    mitre = get_mitre_mapping("Suspicious PowerShell Process")

    assert mitre["technique"] == "T1059.001"


def test_failed_logon():
    mitre = get_mitre_mapping("Windows Failed Logon Detected")

    assert mitre["technique"] == "T1110"


def test_enumeration():
    mitre = get_mitre_mapping("Possible Web Enumeration Detected")

    assert mitre["technique"] == "T1595"


def test_unknown():
    mitre = get_mitre_mapping("Some Random Detection")

    assert mitre["technique"] == "Unknown"