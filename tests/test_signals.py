from phishing_analyzer.email_parser import Attachment, Link, ParsedEmail, parse_eml_file
from phishing_analyzer.signals import (
    check_attachments,
    check_authentication,
    check_domain_age,
    check_reply_to_mismatch,
    check_spoofed_display_name,
    check_suspicious_links,
    check_urgency_language,
)

SAMPLES_DIR = "tests/sample_emails"


def make_parsed_email(**overrides) -> ParsedEmail:
    """Builds a minimal ParsedEmail for testing one signal at a time,
    without needing a full .eml file on disk for every tiny variation."""
    defaults = dict(
        from_header="Someone <someone@example.com>",
        from_name="Someone",
        from_address="someone@example.com",
        reply_to_header=None,
        reply_to_address=None,
        to_header="recipient@example.com",
        subject="a normal subject",
        authentication_results="spf=pass; dkim=pass; dmarc=pass",
        body_text="a normal, boring email body with nothing unusual in it",
        body_html="",
        links=[],
        attachments=[],
        parse_warnings=[],
    )
    defaults.update(overrides)
    return ParsedEmail(**defaults)


# --- authentication -----------------------------------------------------

def test_authentication_all_pass_not_triggered():
    parsed = make_parsed_email(authentication_results="spf=pass; dkim=pass; dmarc=pass")
    result = check_authentication(parsed)
    assert result.triggered is False
    assert result.severity == 0.0


def test_authentication_all_fail_full_severity():
    parsed = make_parsed_email(authentication_results="spf=fail; dkim=fail; dmarc=fail")
    result = check_authentication(parsed)
    assert result.triggered is True
    assert result.severity == 1.0


def test_authentication_partial_fail_partial_severity():
    parsed = make_parsed_email(authentication_results="spf=fail; dkim=pass; dmarc=pass")
    result = check_authentication(parsed)
    assert result.triggered is True
    assert 0.0 < result.severity < 1.0


def test_authentication_missing_header():
    parsed = make_parsed_email(authentication_results=None)
    result = check_authentication(parsed)
    assert result.triggered is True
    assert result.severity == 0.7


# --- reply-to mismatch ---------------------------------------------------

def test_reply_to_no_header_not_triggered():
    parsed = make_parsed_email(reply_to_address=None)
    result = check_reply_to_mismatch(parsed)
    assert result.triggered is False


def test_reply_to_same_domain_not_triggered():
    parsed = make_parsed_email(
        from_address="billing@company.com",
        reply_to_address="billing-team@company.com",
    )
    result = check_reply_to_mismatch(parsed)
    assert result.triggered is False


def test_reply_to_different_domain_triggered():
    parsed = make_parsed_email(
        from_address="billing@company.com",
        reply_to_address="someone@totally-different.net",
    )
    result = check_reply_to_mismatch(parsed)
    assert result.triggered is True
    assert result.severity == 1.0


# --- suspicious links ------------------------------------------------------

def test_no_links_not_triggered():
    parsed = make_parsed_email(links=[])
    result = check_suspicious_links(parsed)
    assert result.triggered is False


def test_clean_links_not_triggered():
    parsed = make_parsed_email(
        links=[
            Link(href="https://company.com/page", display_text="page"),
            Link(href="https://company.com/about", display_text="about us"),
        ]
    )
    result = check_suspicious_links(parsed)
    assert result.triggered is False


def test_shortener_link_triggered():
    parsed = make_parsed_email(links=[Link(href="https://bit.ly/abc123", display_text="click here")])
    result = check_suspicious_links(parsed)
    assert result.triggered is True


def test_mismatched_display_text_triggered():
    parsed = make_parsed_email(
        links=[Link(href="https://evil-domain.com/login", display_text="https://mybank.com/login")]
    )
    result = check_suspicious_links(parsed)
    assert result.triggered is True
    assert "mybank.com" in result.details[0]


def test_lookalike_domain_link_triggered():
    parsed = make_parsed_email(
        links=[Link(href="https://paypa1.com/verify", display_text="verify")]
    )
    result = check_suspicious_links(parsed)
    assert result.triggered is True


# --- urgency language -----------------------------------------------------

def test_no_urgency_language_not_triggered():
    parsed = make_parsed_email(body_text="Here are the notes from our meeting today.")
    result = check_urgency_language(parsed)
    assert result.triggered is False


def test_single_urgency_phrase_mild_severity():
    parsed = make_parsed_email(body_text="Please act now to keep your subscription active.")
    result = check_urgency_language(parsed)
    assert result.triggered is True
    assert result.severity < 0.7


def test_multiple_urgency_phrases_higher_severity():
    parsed = make_parsed_email(
        body_text=(
            "URGENT: act now, your account will be suspended. "
            "This is your final notice, verify immediately."
        )
    )
    result = check_urgency_language(parsed)
    assert result.triggered is True
    assert result.severity > 0.6


# --- spoofed display name --------------------------------------------------

def test_no_display_name_not_triggered():
    parsed = make_parsed_email(from_name="", from_address="someone@example.com")
    result = check_spoofed_display_name(parsed)
    assert result.triggered is False


def test_display_name_matches_real_brand_domain_not_triggered():
    parsed = make_parsed_email(from_name="PayPal", from_address="service@paypal.com")
    result = check_spoofed_display_name(parsed)
    assert result.triggered is False


def test_display_name_impersonates_brand_wrong_domain_triggered():
    parsed = make_parsed_email(from_name="PayPal Security", from_address="alerts@random-mailer.net")
    result = check_spoofed_display_name(parsed)
    assert result.triggered is True
    assert result.severity == 1.0


def test_display_name_no_brand_mention_not_triggered():
    parsed = make_parsed_email(from_name="Jane from Accounting", from_address="jane@company.com")
    result = check_spoofed_display_name(parsed)
    assert result.triggered is False


# --- attachments -----------------------------------------------------------

def test_no_attachments_not_triggered():
    parsed = make_parsed_email(attachments=[])
    result = check_attachments(parsed)
    assert result.triggered is False


def test_pdf_attachment_not_triggered():
    parsed = make_parsed_email(
        attachments=[Attachment(filename="report.pdf", content_type="application/pdf", size_bytes=1024)]
    )
    result = check_attachments(parsed)
    assert result.triggered is False


def test_exe_attachment_triggered():
    parsed = make_parsed_email(
        attachments=[Attachment(filename="setup.exe", content_type="application/octet-stream", size_bytes=2048)]
    )
    result = check_attachments(parsed)
    assert result.triggered is True


def test_double_extension_attachment_max_severity():
    parsed = make_parsed_email(
        attachments=[
            Attachment(filename="invoice.pdf.exe", content_type="application/octet-stream", size_bytes=2048)
        ]
    )
    result = check_attachments(parsed)
    assert result.triggered is True
    assert result.severity == 1.0
    assert "double extension" in result.details[0]


# --- domain age proxy check --------------------------------------------------

def test_suspicious_tld_flagged_by_proxy():
    parsed = make_parsed_email(from_address="noreply@secure-login-portal.top")
    result = check_domain_age(parsed)
    assert result.triggered is True


def test_ordinary_domain_not_flagged_by_proxy():
    parsed = make_parsed_email(from_address="hr@northgatelogistics.com")
    result = check_domain_age(parsed)
    assert result.triggered is False


def test_no_from_domain_not_triggered():
    parsed = make_parsed_email(from_address="")
    result = check_domain_age(parsed)
    assert result.triggered is False


# --- sanity check against real sample files --------------------------------

def test_signals_against_legit_sample_mostly_clean():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/legit_newsletter.eml")
    auth = check_authentication(parsed)
    links = check_suspicious_links(parsed)
    urgency = check_urgency_language(parsed)
    assert auth.triggered is False
    assert links.triggered is False
    assert urgency.triggered is False


def test_signals_against_phishing_sample_mostly_triggered():
    parsed = parse_eml_file(f"{SAMPLES_DIR}/obvious_multi_signal_phishing.eml")
    auth = check_authentication(parsed)
    reply_to = check_reply_to_mismatch(parsed)
    links = check_suspicious_links(parsed)
    urgency = check_urgency_language(parsed)
    display_name = check_spoofed_display_name(parsed)
    attachments = check_attachments(parsed)

    assert auth.triggered is True
    assert reply_to.triggered is True
    assert links.triggered is True
    assert urgency.triggered is True
    assert display_name.triggered is True
    assert attachments.triggered is True
