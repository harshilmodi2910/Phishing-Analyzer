import pytest

from phishing_analyzer.email_parser import (
    EmailParseError,
    get_domain,
    parse_eml_bytes,
    parse_eml_file,
)

SAMPLES_DIR = "tests/sample_emails"


def test_parse_legit_newsletter_basic_fields():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/legit_newsletter.eml")
    assert parsed.from_address == "newsletter@chronicleweekly.com"
    assert parsed.from_name == "Chronicle Weekly"
    assert parsed.subject == "Your weekly digest is here"
    assert parsed.authentication_results is not None
    assert "spf=pass" in parsed.authentication_results


def test_parse_extracts_plain_text_links():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/legit_newsletter.eml")
    hrefs = [link.href for link in parsed.links]
    assert "https://chronicleweekly.com/digest/week-37" in hrefs
    assert "https://chronicleweekly.com/preferences" in hrefs


def test_parse_extracts_html_links_with_display_text():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/obvious_multi_signal_phishing.eml")
    matching = [l for l in parsed.links if l.href == "https://bit.ly/appleVerify"]
    assert len(matching) == 1
    assert "appleid.apple.com" in matching[0].display_text


def test_parse_extracts_attachments():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/double_extension_attachment.eml")
    assert len(parsed.attachments) == 1
    assert parsed.attachments[0].filename == "invoice.pdf.exe"


def test_parse_reply_to_mismatch_captured():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/reply_to_mismatch.eml")
    assert parsed.reply_to_address == "finance@collectionservices-llc.com"
    assert parsed.from_address == "billing@statecollege.edu"


def test_parse_no_links_email_has_empty_link_list():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/legit_no_links.eml")
    assert parsed.links == []


def test_parse_missing_authentication_results_header():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/suspicious_tld_no_auth_header.eml")
    assert parsed.authentication_results is None
    assert any("Authentication-Results" in w for w in parsed.parse_warnings)


def test_parse_file_not_found_raises():
    with pytest.raises(EmailParseError):
        parse_eml_file("tests/sample_emails/does_not_exist.eml")


def test_parse_empty_bytes_raises():
    with pytest.raises(EmailParseError):
        parse_eml_bytes(b"")


def test_parse_whitespace_only_bytes_raises():
    with pytest.raises(EmailParseError):
        parse_eml_bytes(b"   \n\n   ")


def test_parse_no_headers_at_all_raises():
    with pytest.raises(EmailParseError):
        parse_eml_bytes(b"just some random text with no headers at all, no colons even")


def test_parse_missing_from_header_does_not_crash():
    raw = (
        b"Subject: no sender here\r\n"
        b"To: someone@example.com\r\n"
        b"\r\n"
        b"body text\r\n"
    )
    parsed = parse_eml_bytes(raw)
    assert parsed.from_address == ""
    assert any("From" in w for w in parsed.parse_warnings)


def test_parse_missing_subject_recorded_as_warning():
    raw = (
        b"From: sender@example.com\r\n"
        b"To: someone@example.com\r\n"
        b"\r\n"
        b"body text\r\n"
    )
    parsed = parse_eml_bytes(raw)
    assert parsed.subject is None
    assert any("Subject" in w for w in parsed.parse_warnings)


def test_parse_malformed_multipart_does_not_raise():
    # missing closing boundary, real world mail servers produce garbage
    # like this more often than you'd think
    raw = (
        b"From: sender@example.com\r\n"
        b"Subject: broken mime\r\n"
        b'Content-Type: multipart/mixed; boundary="X"\r\n'
        b"\r\n"
        b"--X\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"partial body with no closing boundary"
    )
    parsed = parse_eml_bytes(raw)
    assert parsed.from_address == "sender@example.com"


@pytest.mark.parametrize(
    "value,expected",
    [
        ("user@example.com", "example.com"),
        ("User@Example.COM", "example.com"),
        ("https://sub.example.com/path", "sub.example.com"),
        ("http://example.com:8080/x", "example.com"),
        ("example.com/some/path", "example.com"),
        ("", ""),
    ],
)
def test_get_domain(value, expected):
    assert get_domain(value) == expected
