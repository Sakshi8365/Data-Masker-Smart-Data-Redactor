import re

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"\b(?:\+?\d{1,3}[\s-]?)?(?:\(?\d{3}\)?[\s-]?)?\d{3}[\s-]?\d{4}\b")
CREDIT_CARD = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
SSN = re.compile(r"\b\d{3}-?\d{2}-?\d{4}\b")
IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
IPV6 = re.compile(
    r"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|"
    r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}:\b|"
    r"\b:(?::[A-Fa-f0-9]{1,4}){1,7}\b|"
    r"\b(?:[A-Fa-f0-9]{1,4}:){1,6}:(?:[A-Fa-f0-9]{1,4})\b"
)
IBAN = re.compile(r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}\b")

DEFAULT_PATTERNS = {
    "email": EMAIL,
    "phone": PHONE,
    "credit_card": CREDIT_CARD,
    "ssn": SSN,
    "ipv4": IPV4,
    "ipv6": IPV6,
    "iban": IBAN,
}
