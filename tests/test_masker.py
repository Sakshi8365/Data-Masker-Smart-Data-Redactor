from data_masker.masker import Masker
from data_masker.rules import Rules
from data_masker.token_store import TokenStore


def test_hash_strategy():
    r = Rules.load(None)
    r.strategies["email"] = "hash"
    m = Masker(r, token_store=TokenStore(path=".test_tokens.json"))
    out = m.mask_cell("alice@example.com")
    assert out != "alice@example.com"
    SHA256_HEX_LEN = 64
    assert len(out) == SHA256_HEX_LEN


def test_tokenize_strategy_stable(tmp_path):
    tok_path = tmp_path / "tokens.json"
    r = Rules.load(None)
    r.strategies["email"] = "tokenize"
    m = Masker(r, token_store=TokenStore(path=str(tok_path)))
    out1 = m.mask_cell("alice@example.com")
    out2 = m.mask_cell("alice@example.com")
    assert out1 == out2


def test_partial_strategy():
    r = Rules.load(None)
    r.strategies["phone"] = "partial"
    r.options["partial_keep_last"] = 4
    m = Masker(r)
    out = m.mask_cell("202-555-0133")
    assert out.endswith("0133")


def test_column_strategy_overrides():
    r = Rules.load(None)
    r.columns["ssn"] = {"strategy": "tokenize"}
    m = Masker(r)
    out = m.mask_cell("123-45-6789", column="ssn")
    assert out.startswith("TOK-")


def test_non_pii_unchanged():
    r = Rules.load(None)
    m = Masker(r)
    out = m.mask_cell("Hello World")
    assert out == "Hello World"

def test_credit_card_luhn_valid_only():
    r = Rules.load(None)
    # 4111 1111 1111 1111 is a common test Visa number (valid Luhn)
    m = Masker(r)
    out_valid = m.mask_cell("4111 1111 1111 1111")
    assert out_valid != "4111 1111 1111 1111"
    # Random 16-digit number likely fails Luhn
    out_invalid = m.mask_cell("1234567890123456")
    # Should not be masked since detector should ignore it
    assert out_invalid == "1234567890123456"
