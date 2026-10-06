"""
Individual detection signals.

Every function in here looks at one narrow thing and returns a SignalResult.
None of these functions know anything about scoring weights, that happens
later in scorer.py. Keeping them separate means I can test "does the SPF
check work" completely on its own without dragging the rest of the scoring
pipeline into the test.

Severity is a float from 0.0 to 1.0. Most signals are just on/off (1.0 or
not triggered at all) but a few, like urgency language or suspicious links,
can fire a little or a lot depending on how many hits there are, so severity
gives the scorer something more useful than a flat yes/no.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .email_parser import ParsedEmail, get_domain

try:
    import whois as whois_lib  # python-whois, optional dependency
except ImportError:  # pragma: no cover
    whois_lib = None


@dataclass
class SignalResult:
    key: str
    triggered: bool
    severity: float  # 0.0 to 1.0
    summary: str
    details: List[str] = field(default_factory=list)


# A handful of brands that show up constantly in phishing samples. This is
# nowhere close to exhaustive, it is just enough to make the demo signals
# fire on realistic sample data. A real deployment would want a much bigger
# and regularly updated list, probably pulled from somewhere external
# instead of hardcoded like this.
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "google": "google.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "chase": "chase.com",
    "netflix": "netflix.com",
    "irs": "irs.gov",
    "usps": "usps.com",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
    "linkedin": "linkedin.com",
    "docusign": "docusign.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc",
}

URGENCY_PHRASES = [
    r"act now", r"verify your account", r"account.{0,15}suspend",
    r"immediate(ly)? (action|attention)", r"urgent(ly)?",
    r"confirm your identity", r"unusual activity", r"unauthorized (access|login)",
    r"limited time", r"failure to (comply|verify)", r"click here immediately",
    r"your account (will be|has been) (closed|locked|suspended|restricted)",
    r"final notice", r"security alert", r"password (will )?expire",
    r"avoid (suspension|termination|closure)", r"within 24 hours",
    r"verify (now|immediately)",
]
URGENCY_PATTERN = re.compile("|".join(URGENCY_PHRASES), re.IGNORECASE)

EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "jar", "ps1", "msi", "wsf", "hta", "cpl", "reg",
}

DOCUMENT_LOOKING_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg",
    "jpeg", "png", "zip", "csv",
}

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "support", "account", "verify", "win", "loan", "bid",
}


def check_authentication(parsed: ParsedEmail) -> SignalResult:
    """Look at SPF/DKIM/DMARC status from the Authentication-Results header.

    This trusts the Authentication-Results header, which means it trusts
    whatever mail server added that header (normally the receiving server,
    before the message ever reaches the analyzer). That is a real
    limitation, not an oversight, see the README for more on this.
    """
    auth_header = parsed.authentication_results

    if not auth_header:
        return SignalResult(
            key="authentication",
            triggered=True,
            severity=0.7,
            summary="no Authentication-Results header present",
            details=["cannot confirm SPF, DKIM, or DMARC status without this header"],
        )

    spf = _extract_auth_value(auth_header, "spf")
    dkim = _extract_auth_value(auth_header, "dkim")
    dmarc = _extract_auth_value(auth_header, "dmarc")

    details = []
    fail_count = 0
    checked_count = 0

    for name, result in (("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)):
        if result is None:
            details.append(f"{name} result not found in header")
            continue
        checked_count += 1
        details.append(f"{name} = {result}")
        if result in ("fail", "softfail", "permerror", "temperror"):
            fail_count += 1
        elif result == "none":
            fail_count += 0.5

    if checked_count == 0:
        return SignalResult(
            key="authentication",
            triggered=True,
            severity=0.6,
            summary="Authentication-Results header present but unreadable",
            details=details,
        )

    severity = min(fail_count / checked_count, 1.0) if checked_count else 0.0
    triggered = severity > 0

    if triggered:
        summary = f"{fail_count:g} of {checked_count} auth checks failed or missing"
    else:
        summary = "SPF, DKIM, and DMARC all passed"

    return SignalResult(
        key="authentication",
        triggered=triggered,
        severity=severity,
        summary=summary,
        details=details,
    )


def _extract_auth_value(header: str, mechanism: str) -> Optional[str]:
    match = re.search(rf"{mechanism}\s*=\s*(\w+)", header, re.IGNORECASE)
    return match.group(1).lower() if match else None


def check_reply_to_mismatch(parsed: ParsedEmail) -> SignalResult:
    if not parsed.reply_to_address:
        return SignalResult(
            key="reply_to_mismatch",
            triggered=False,
            severity=0.0,
            summary="no Reply-To header set",
        )

    from_domain = get_domain(parsed.from_address)
    reply_domain = get_domain(parsed.reply_to_address)

    if not from_domain or not reply_domain:
        return SignalResult(
            key="reply_to_mismatch",
            triggered=False,
            severity=0.0,
            summary="could not compare From and Reply-To domains",
        )

    if from_domain != reply_domain:
        return SignalResult(
            key="reply_to_mismatch",
            triggered=True,
            severity=1.0,
            summary=f"Reply-To domain ({reply_domain}) does not match From domain ({from_domain})",
            details=[f"From: {parsed.from_address}", f"Reply-To: {parsed.reply_to_address}"],
        )

    return SignalResult(
        key="reply_to_mismatch",
        triggered=False,
        severity=0.0,
        summary="Reply-To domain matches From domain",
    )


def check_suspicious_links(parsed: ParsedEmail) -> SignalResult:
    if not parsed.links:
        return SignalResult(
            key="suspicious_links",
            triggered=False,
            severity=0.0,
            summary="no links found in the body",
        )

    flagged_details = []
    flag_count = 0

    for link in parsed.links:
        href_domain = get_domain(link.href)
        reasons = []

        if href_domain in URL_SHORTENERS:
            reasons.append("uses a known URL shortener")

        display_domain = get_domain(link.display_text) if "://" in link.display_text or "." in link.display_text else ""
        if display_domain and href_domain and display_domain != href_domain:
            reasons.append(
                f"display text shows '{display_domain}' but the link actually goes to '{href_domain}'"
            )

        lookalike_of = _lookalike_brand(href_domain)
        if lookalike_of:
            reasons.append(f"domain looks like a misspelled or lookalike version of {lookalike_of}")

        if reasons:
            flag_count += 1
            flagged_details.append(f"{link.href}: {', '.join(reasons)}")

    if flag_count == 0:
        return SignalResult(
            key="suspicious_links",
            triggered=False,
            severity=0.0,
            summary=f"checked {len(parsed.links)} link(s), nothing suspicious found",
        )

    ratio = flag_count / len(parsed.links)
    severity = min(0.4 + ratio * 0.6, 1.0)

    return SignalResult(
        key="suspicious_links",
        triggered=True,
        severity=severity,
        summary=f"{flag_count} of {len(parsed.links)} link(s) flagged as suspicious",
        details=flagged_details,
    )


def _lookalike_brand(domain: str) -> Optional[str]:
    if not domain:
        return None

    base = domain.split(".")[0]

    for brand, real_domain in KNOWN_BRANDS.items():
        brand_key = brand.replace(" ", "")
        if domain == real_domain:
            continue
        if brand_key in base and domain != real_domain:
            # something like "paypal-security.net" or "paypal.security-check.xyz"
            return brand
        if _levenshtein(base, real_domain.split(".")[0]) <= 2 and base != real_domain.split(".")[0]:
            return brand

    return None


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current_row = [i]
        for j, cb in enumerate(b, 1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row

    return previous_row[-1]


def check_urgency_language(parsed: ParsedEmail) -> SignalResult:
    combined_text = f"{parsed.subject or ''} {parsed.body_text} {parsed.body_html}"
    matches = URGENCY_PATTERN.findall(combined_text)
    hit_count = len(matches)

    if hit_count == 0:
        return SignalResult(
            key="urgency_language",
            triggered=False,
            severity=0.0,
            summary="no urgency or pressure phrases found",
        )

    severity = min(0.4 + (hit_count - 1) * 0.25, 1.0)

    unique_phrases = sorted(set(m.lower() for m in matches if isinstance(m, str) and m))

    return SignalResult(
        key="urgency_language",
        triggered=True,
        severity=severity,
        summary=f"found {hit_count} urgency/pressure phrase match(es)",
        details=unique_phrases[:10],
    )


def check_spoofed_display_name(parsed: ParsedEmail) -> SignalResult:
    if not parsed.from_name:
        return SignalResult(
            key="spoofed_display_name",
            triggered=False,
            severity=0.0,
            summary="no display name set on From header",
        )

    name_lower = parsed.from_name.lower()
    from_domain = get_domain(parsed.from_address)

    for brand, real_domain in KNOWN_BRANDS.items():
        if brand not in name_lower:
            continue
        if from_domain == real_domain or from_domain.endswith("." + real_domain):
            continue
        # the display name claims to be this brand but the actual sending
        # domain is not that brand's domain at all
        severity = 1.0 if _levenshtein(from_domain, real_domain) > 3 else 0.6
        return SignalResult(
            key="spoofed_display_name",
            triggered=True,
            severity=severity,
            summary=f"display name says '{parsed.from_name}' but sends from '{from_domain}', not {real_domain}",
            details=[f"From header: {parsed.from_header}"],
        )

    return SignalResult(
        key="spoofed_display_name",
        triggered=False,
        severity=0.0,
        summary="display name does not appear to impersonate a known brand",
    )


def check_attachments(parsed: ParsedEmail) -> SignalResult:
    if not parsed.attachments:
        return SignalResult(
            key="attachment_flags",
            triggered=False,
            severity=0.0,
            summary="no attachments",
        )

    flagged = []

    for att in parsed.attachments:
        if not att.filename:
            continue
        name_lower = att.filename.lower()
        parts = name_lower.split(".")
        if len(parts) < 2:
            continue

        final_ext = parts[-1]

        if len(parts) >= 3 and parts[-2] in DOCUMENT_LOOKING_EXTENSIONS and final_ext in EXECUTABLE_EXTENSIONS:
            flagged.append(f"{att.filename}: double extension trick ('.{parts[-2]}.{final_ext}')")
        elif final_ext in EXECUTABLE_EXTENSIONS:
            flagged.append(f"{att.filename}: executable or script attachment (.{final_ext})")

    if not flagged:
        return SignalResult(
            key="attachment_flags",
            triggered=False,
            severity=0.0,
            summary=f"{len(parsed.attachments)} attachment(s), none flagged",
        )

    severity = 1.0 if any("double extension" in f for f in flagged) else 0.8

    return SignalResult(
        key="attachment_flags",
        triggered=True,
        severity=severity,
        summary=f"{len(flagged)} attachment(s) flagged",
        details=flagged,
    )


def check_domain_age(parsed: ParsedEmail) -> SignalResult:
    """Flag domains that look newly registered.

    I originally wanted this to do a live WHOIS lookup every time, but that
    turned out to be a bad idea for a project other people are going to
    clone and run. WHOIS servers rate limit, some domains use privacy
    proxies that hide the real creation date, and the whole check would
    silently fail or hang on any machine without outbound network access.
    So this tries a live lookup first if the python-whois package is
    installed, and falls back to a heuristic based on the TLD and shape of
    the domain name if that lookup is not available or does not return a
    usable date. The fallback is not as good as real WHOIS data. It is a
    reasonable stand in for a portfolio project, not something I would
    trust in production.
    """
    from_domain = get_domain(parsed.from_address)
    if not from_domain:
        return SignalResult(
            key="newly_registered_domain",
            triggered=False,
            severity=0.0,
            summary="no domain to check",
        )

    age_days = _lookup_domain_age_days(from_domain)

    if age_days is not None:
        if age_days < 30:
            return SignalResult(
                key="newly_registered_domain",
                triggered=True,
                severity=1.0,
                summary=f"{from_domain} was registered {age_days} day(s) ago",
            )
        if age_days < 90:
            return SignalResult(
                key="newly_registered_domain",
                triggered=True,
                severity=0.6,
                summary=f"{from_domain} was registered {age_days} day(s) ago",
            )
        return SignalResult(
            key="newly_registered_domain",
            triggered=False,
            severity=0.0,
            summary=f"{from_domain} was registered {age_days} day(s) ago, not recent",
        )

    return _domain_age_proxy_check(from_domain)


def _lookup_domain_age_days(domain: str) -> Optional[int]:
    if whois_lib is None:
        return None

    try:
        import datetime

        record = whois_lib.whois(domain)
        creation = record.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if creation is None:
            return None
        if isinstance(creation, str):
            return None
        now = datetime.datetime.now(tz=getattr(creation, "tzinfo", None))
        return (now - creation).days
    except Exception:
        return None


def _domain_age_proxy_check(domain: str) -> SignalResult:
    tld = domain.split(".")[-1] if "." in domain else ""
    base = domain.split(".")[0]

    reasons = []
    severity = 0.0

    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"'.{tld}' is a cheap TLD that shows up disproportionately often in phishing")
        severity += 0.4

    hyphen_count = base.count("-")
    if hyphen_count >= 2:
        reasons.append(f"domain name has {hyphen_count} hyphens, which is unusual for a real brand domain")
        severity += 0.2

    digit_count = sum(c.isdigit() for c in base)
    if digit_count >= 3:
        reasons.append("domain name has several digits mixed into it")
        severity += 0.2

    if len(base) > 20:
        reasons.append("domain name is unusually long")
        severity += 0.1

    severity = min(severity, 1.0)

    if not reasons:
        return SignalResult(
            key="newly_registered_domain",
            triggered=False,
            severity=0.0,
            summary=f"no WHOIS data available for {domain}, and it does not match any of the proxy red flags",
        )

    return SignalResult(
        key="newly_registered_domain",
        triggered=severity >= 0.4,
        severity=severity,
        summary=f"no WHOIS data available for {domain}, but it matches {len(reasons)} proxy red flag(s)",
        details=reasons,
    )


def run_all_signals(parsed: ParsedEmail) -> List[SignalResult]:
    return [
        check_authentication(parsed),
        check_reply_to_mismatch(parsed),
        check_suspicious_links(parsed),
        check_urgency_language(parsed),
        check_spoofed_display_name(parsed),
        check_attachments(parsed),
        check_domain_age(parsed),
    ]
