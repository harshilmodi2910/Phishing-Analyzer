"""
Parsing utilities for the phishing analyzer.

This module wraps Python's built in email library and pulls out the pieces
the rest of the project needs: headers, the body (plain text and html),
links found in the body, and attachment metadata. Scoring and signal logic
does not live here on purpose, this file's only job is turning raw bytes
into something the signal checks can work with.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

ANCHOR_TEXT_PATTERN = re.compile(
    r'<a[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)

BARE_HREF_PATTERN = re.compile(
    r'href\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

PLAIN_URL_PATTERN = re.compile(
    r'(https?://[^\s<>"\')\]]+)',
    re.IGNORECASE,
)

TAG_STRIP_PATTERN = re.compile(r'<[^>]+>')


class EmailParseError(Exception):
    """Raised when a file can't reasonably be treated as an email."""


@dataclass
class Attachment:
    filename: Optional[str]
    content_type: str
    size_bytes: int


@dataclass
class Link:
    href: str
    display_text: str = ""


@dataclass
class ParsedEmail:
    from_header: str
    from_name: str
    from_address: str
    reply_to_header: Optional[str]
    reply_to_address: Optional[str]
    to_header: Optional[str]
    subject: Optional[str]
    authentication_results: Optional[str]
    body_text: str
    body_html: str
    links: List[Link] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    parse_warnings: List[str] = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)


def parse_eml_file(path: str) -> ParsedEmail:
    file_path = Path(path)
    if not file_path.exists():
        raise EmailParseError(f"file not found: {path}")
    if not file_path.is_file():
        raise EmailParseError(f"not a file: {path}")
    return parse_eml_bytes(file_path.read_bytes())


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    warnings: List[str] = []

    if not raw_bytes.strip():
        raise EmailParseError("file is empty")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    except Exception as exc:
        raise EmailParseError(f"could not parse as an email: {exc}") from exc

    # policy.default is forgiving about malformed input, it will happily
    # hand back an EmailMessage with nothing in it rather than raising, so
    # we check for that case ourselves instead of trusting parsebytes to
    # tell us something went wrong.
    if not msg.keys():
        raise EmailParseError(
            "no headers found, this does not look like a real .eml file"
        )

    raw_headers = {}
    for key in msg.keys():
        raw_headers.setdefault(key, msg.get_all(key))

    from_header = msg.get("From", "") or ""
    from_name, from_address = parseaddr(from_header)
    if not from_address:
        warnings.append("missing or unparseable From header")

    reply_to_header = msg.get("Reply-To")
    reply_to_address = None
    if reply_to_header:
        _, reply_to_address = parseaddr(reply_to_header)
        if not reply_to_address:
            warnings.append("Reply-To header present but could not be parsed")

    to_header = msg.get("To")
    subject = msg.get("Subject")
    if subject is None:
        warnings.append("missing Subject header")

    auth_results = msg.get("Authentication-Results")
    if auth_results is None:
        warnings.append(
            "missing Authentication-Results header, SPF/DKIM/DMARC status is unknown"
        )

    body_text, body_html = _extract_body(msg, warnings)
    links = _extract_links(body_html, body_text)
    attachments = _extract_attachments(msg)

    return ParsedEmail(
        from_header=from_header,
        from_name=from_name,
        from_address=from_address.lower() if from_address else "",
        reply_to_header=reply_to_header,
        reply_to_address=reply_to_address.lower() if reply_to_address else None,
        to_header=to_header,
        subject=subject,
        authentication_results=auth_results,
        body_text=body_text,
        body_html=body_html,
        links=links,
        attachments=attachments,
        parse_warnings=warnings,
        raw_headers=raw_headers,
    )


def _extract_body(msg: EmailMessage, warnings: List[str]) -> Tuple[str, str]:
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = part.get_content_disposition()
            if disposition == "attachment":
                continue
            if content_type not in ("text/plain", "text/html"):
                continue
            try:
                content = part.get_content()
            except Exception:
                warnings.append(f"could not decode a {content_type} part, skipped it")
                continue
            if content_type == "text/plain" and not body_text:
                body_text = content
            elif content_type == "text/html" and not body_html:
                body_html = content
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            warnings.append("could not decode message body")
            content = ""
        if content_type == "text/html":
            body_html = content
        else:
            body_text = content

    if not body_text and not body_html:
        warnings.append("no readable body content found")

    return body_text, body_html


def _extract_links(body_html: str, body_text: str) -> List[Link]:
    links: List[Link] = []
    seen_hrefs = set()

    if body_html:
        for href, display in ANCHOR_TEXT_PATTERN.findall(body_html):
            clean_display = TAG_STRIP_PATTERN.sub("", display).strip()
            href_clean = href.strip()
            if href_clean not in seen_hrefs:
                seen_hrefs.add(href_clean)
                links.append(Link(href=href_clean, display_text=clean_display))

        # the anchor pattern above requires a closing </a> with text in
        # between, which most real emails have, but just in case something
        # odd slips through (self closing tags, broken markup) grab any
        # remaining bare hrefs too so we don't silently miss a link
        for href in BARE_HREF_PATTERN.findall(body_html):
            href_clean = href.strip()
            if href_clean not in seen_hrefs:
                seen_hrefs.add(href_clean)
                links.append(Link(href=href_clean, display_text=""))

    for url in PLAIN_URL_PATTERN.findall(body_text):
        url_clean = url.strip()
        if url_clean not in seen_hrefs:
            seen_hrefs.add(url_clean)
            links.append(Link(href=url_clean, display_text=url_clean))

    return links


def _extract_attachments(msg: EmailMessage) -> List[Attachment]:
    attachments: List[Attachment] = []
    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition != "attachment" and not filename:
            continue
        try:
            payload = part.get_content()
            if isinstance(payload, bytes):
                size = len(payload)
            elif isinstance(payload, str):
                size = len(payload.encode("utf-8", errors="ignore"))
            else:
                size = 0
        except Exception:
            size = 0
        attachments.append(
            Attachment(
                filename=filename,
                content_type=part.get_content_type(),
                size_bytes=size,
            )
        )
    return attachments


def get_domain(address_or_url: str) -> str:
    """Pull a lowercase domain out of an email address or a URL.

    Works for both because a lot of the signal checks need to compare
    a sender's domain against a link's domain and I did not want two
    separate helpers that basically do the same split on '@' or '//'.
    """
    if not address_or_url:
        return ""

    if "@" in address_or_url and "://" not in address_or_url:
        return address_or_url.rsplit("@", 1)[-1].lower().strip()

    try:
        candidate = address_or_url if "://" in address_or_url else f"//{address_or_url}"
        parsed = urlparse(candidate)
        netloc = parsed.netloc or parsed.path
        return netloc.lower().split(":")[0].split("/")[0]
    except Exception:
        return ""
