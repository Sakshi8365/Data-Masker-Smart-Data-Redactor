from data_masker.masker import Masker
from data_masker.rules import Rules


def test_ipv6_detection_and_mask():
    r = Rules.load(None)
    m = Masker(r)
    # Valid IPv6
    ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    out = m.mask_cell(ip)
    assert out != ip
    # Invalid IPv6-like string should remain
    invalid = "2001:0db8:85a3:0000:0000:8a2e:0370:ZZZZ"
    out2 = m.mask_cell(invalid)
    assert out2 == invalid


essa_iban = "GB82 WEST 1234 5698 7654 32".replace(" ", "")

def test_iban_detection_and_mask():
    r = Rules.load(None)
    m = Masker(r)
    out = m.mask_cell(essa_iban)
    assert out != essa_iban
    invalid_iban = "GB00 WEST 1234 5698 7654 32".replace(" ", "")
    out2 = m.mask_cell(invalid_iban)
    assert out2 == invalid_iban
