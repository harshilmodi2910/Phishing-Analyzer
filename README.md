# phishnet

A command line tool that takes a raw `.eml` file and scores how likely it is
to be phishing. I built this as a portfolio project while finishing my
master's in cybersecurity management, mostly because I wanted something that
went a level deeper than "does this email look sketchy" and actually broke
the decision down into separate, inspectable checks.

It is not a spam filter and it does not claim to catch everything. More on
that in the limitations section below, which I'd actually read before you
trust this on real email.

## What it does

You give it a `.eml` file. It parses the headers and body, runs seven
detection checks against it, and outputs a score from 0 to 100 along with a
low / medium / high risk label. Each check can trigger partially, not just
on or off, so an email with one weak signal scores differently than one with
five strong ones.

The seven signals:

- **Authentication status** — reads the `Authentication-Results` header and
  checks whether SPF, DKIM, and DMARC passed. If the header is missing
  entirely, that counts against the email too, since a legitimate mail
  server almost always adds one.
- **Reply-To mismatch** — flags it when the Reply-To address is on a
  different domain than the From address. A lot of phishing wants your
  reply to go somewhere other than where the email claims to come from.
- **Suspicious links** — checks for URL shorteners, links where the visible
  text shows one domain but the actual href goes somewhere else, and domains
  that look like a misspelled version of a well known brand (paypa1.com
  instead of paypal.com, that kind of thing).
- **Urgency language** — scans the subject and body for pressure phrases,
  "act now," "your account will be suspended," "verify immediately," stuff
  like that. Counts how many distinct hits there are and scales severity
  accordingly.
- **Spoofed display name** — catches when the display name claims to be a
  known brand ("PayPal Security") but the actual sending domain has nothing
  to do with that brand.
- **Attachment flags** — looks for executable or script attachments, and
  specifically for the double extension trick, something like
  `invoice.pdf.exe`, where the filename is trying to look like a document.
- **Newly registered domain** — tries a live WHOIS lookup if the
  `python-whois` package is installed, and if that's not available or comes
  back empty, falls back to a heuristic based on the TLD and shape of the
  domain name. I go into why in the design decisions section.

## Installation

```bash
git clone https://github.com/harshilmodi2910/phishnet.git
cd phishnet
pip install -r requirements.txt
```

The core tool only needs the standard library. `python-whois` is listed in
requirements.txt because it enables the live domain age lookup, but if you
skip installing it the tool still runs fine, it just uses the proxy check
for every domain instead.

## Usage

Analyze a single file:

```bash
python -m phishing_analyzer.cli --file sample.eml
```

Write the full report to JSON instead of (or in addition to) the terminal
output:

```bash
python -m phishing_analyzer.cli --file sample.eml --json-out report.json
```

Scan every `.eml` file in a directory at once:

```bash
python -m phishing_analyzer.cli --batch tests/sample_emails/
```

Other flags I ended up adding, not because the spec demanded them but
because I kept wanting them while testing:

- `--verbose` prints the detail lines under each signal (which links were
  flagged and why, which auth checks failed, etc.) instead of just the
  one-line summary.
- `--quiet` suppresses the printed report, useful if you're running this in
  a script and only care about the JSON output file.
- `--weights-config path/to/weights.json` lets you swap in your own signal
  weights without touching any code. The file just needs to be a JSON
  object mapping signal names to point values, see `scorer.py` for the
  exact keys it expects.

Example output:

```
file:      tests/sample_emails/obvious_multi_signal_phishing.eml
from:      Apple ID Support <account@app1e.com>
subject:   URGENT: Your Apple ID has been locked, verify immediately

score:     83.2 / 100
risk:      HIGH

signals:
  [X] authentication             + 22.0  3 of 3 auth checks failed or missing
  [X] reply_to_mismatch          +  8.0  Reply-To domain (totally-different-domain.net) does not match From domain (app1e.com)
  [X] suspicious_links           + 20.0  1 of 1 link(s) flagged as suspicious
  [X] urgency_language           +  8.0  found 6 urgency/pressure phrase match(es)
  [X] spoofed_display_name       + 10.2  display name says 'Apple ID Support' but sends from 'app1e.com', not apple.com
  [X] attachment_flags           + 15.0  1 attachment(s) flagged
  [ ] newly_registered_domain    +  0.0  no WHOIS data available for app1e.com, and it does not match any of the proxy red flags
```

## Scoring and weights

Every signal has a weight, the number of points it contributes if it fires
at full severity. Default weights:

| signal | weight |
|---|---|
| authentication | 22 |
| suspicious_links | 20 |
| spoofed_display_name | 17 |
| attachment_flags | 15 |
| newly_registered_domain | 10 |
| reply_to_mismatch | 8 |
| urgency_language | 8 |

These add up to 100, so a hypothetical email that triggers every single
signal at full severity lands at exactly 100. I want to be upfront that I
picked these numbers based on which signals felt like the strongest
indicators to me, not from training this against a labeled dataset of real
phishing and legitimate email, because I don't have one. Authentication
failures got the highest weight because SPF/DKIM/DMARC are at least
technically verifiable, versus something like urgency language which is
easy for an attacker to just... not include. Urgency language got the
lowest weight for that same reason, plenty of legitimate emails use
"urgent" too (looking at you, every calendar reminder I've ever gotten from
IT).

If you disagree with these numbers, that's kind of the point of making them
configurable. Write your own weights.json and pass it with
`--weights-config`.

Risk labels are also threshold based and also not calibrated against
anything real: 0 to 29 is low, 30 to 59 is medium, 60 and up is high.

## Sample data

`tests/sample_emails/` has ten `.eml` files I wrote by hand, a mix of clean
and phishing, each one built to isolate a different combination of signals:

- `legit_newsletter.eml` and `legit_no_links.eml` — clean, should score low
- `spf_fail_clean_links.eml` — auth fails but the links are fine
- `lookalike_domain_valid_spf.eml` — domain is a lookalike (paypa1.com) but
  since the attacker owns that domain outright, SPF actually passes
- `urgency_shortlink_auth_pass.eml` — urgency language and a shortened link,
  but authentication passes
- `spoofed_display_name_dmarc_fail.eml` — display name claims Bank of
  America, domain doesn't match, DMARC fails
- `double_extension_attachment.eml` — the invoice.pdf.exe trick
- `suspicious_tld_no_auth_header.eml` — no Authentication-Results header at
  all, domain on a cheap/abused TLD
- `reply_to_mismatch.eml` — From and Reply-To on different domains,
  otherwise clean
- `obvious_multi_signal_phishing.eml` — basically everything at once, this
  one scores 83 out of 100

None of these are real emails, I made them up to exercise specific code
paths. The "attachments" are fake binary garbage, not actual executables,
don't worry.

## Testing

```bash
pytest tests/ -v
```

63 tests across three files. `test_parser.py` covers the email parsing
layer on its own, including malformed input, missing headers, and empty
files. `test_signals.py` tests each of the seven signals in isolation using
small hand built `ParsedEmail` objects, so a broken SPF check gets caught
by a test that has nothing to do with link checking. `test_scorer.py` tests
the weighting and threshold math directly, without needing to parse an
actual email at all.

GitHub Actions runs the suite on push and PR against Python 3.10 through
3.12, config is in `.github/workflows/tests.yml`.

One small thing that tripped me up while setting this up: there's an
empty `conftest.py` sitting in the project root. If you run `pytest`
directly instead of `python -m pytest`, pytest doesn't automatically put
the project root on `sys.path`, so `tests/test_parser.py` can't find the
`phishing_analyzer` package and fails with a `ModuleNotFoundError`. An
empty `conftest.py` at the root is apparently the standard fix, pytest
puts the directory containing a conftest.py on the path during
collection. Both `pytest tests/` and `python -m pytest tests/` work fine
now, I just didn't know this was a thing until it broke on me.

## A design decision I went back and forth on: live WHOIS vs a heuristic

The domain age check was the one I struggled with the most. My first
instinct was obviously to do a real WHOIS lookup, since "when was this
domain registered" is a genuinely useful phishing signal, most legitimate
businesses aren't sending mail from a domain that's four days old.

But once I actually wired up `python-whois` and started testing it, a few
problems showed up. WHOIS servers rate limit aggressively, and if you're
batch scanning a folder of twenty emails that's twenty lookups hitting
different registrars, some of which will just refuse to respond after a
handful of requests. A decent number of domains also use privacy proxy
registration, which means the "creation date" WHOIS gives you back is for
the proxy service, not the actual domain, so it's not even accurate half
the time. And then there's the practical issue that this is a project
someone is going to clone and run on a machine that might not have outbound
network access to arbitrary WHOIS ports at all, especially in a sandboxed
or CI environment.

I thought about just dropping the check entirely. But domain age is a real
signal and I didn't want to lose it. So what I landed on is a tiered
approach: try the live WHOIS lookup if the library is installed and the
lookup actually returns a usable creation date, and if that fails for any
reason, silently fall back to a heuristic that looks at the TLD (is it one
of the cheap ones that shows up constantly in abuse reports, .tk, .xyz,
.top, that kind of thing) plus some shape based checks on the domain name
itself, excessive hyphens, a pile of digits mixed into the name, unusual
length. It's a worse signal than real WHOIS data. I know that. But it
degrades gracefully instead of just not working, and it means the tool
behaves the same way whether or not you bothered installing the optional
dependency. I'm still not fully sure this was the right tradeoff, a
stricter version of me might say a bad signal is worse than no signal
because it creates false confidence, but I'd rather have something that
catches the more obvious "totally-random-string.top" cases than nothing at
all.

## Limitations, and where this can go wrong

I want to be honest about what this tool is and isn't.

**False positives are a real risk.** A legitimate company that had a DNS
misconfiguration and is temporarily failing SPF will get penalized the same
as an attacker. A marketing email with "limited time offer, act now" in it
is going to trip the urgency check even though it's just normal marketing
copy. I did not build in any allowlisting for known-good domains, mostly
because for a portfolio project that felt out of scope, but a production
version of this would need it.

**The authentication check trusts the Authentication-Results header**,
which means it trusts whatever mail server added that header before the
message got to this tool. If you feed it an `.eml` file that never actually
passed through a real mail server (like, say, all ten of my sample files,
which I wrote by hand), that header is just whatever I typed in. This tool
has no way to independently re-verify SPF or DKIM itself, it's reading a
claim, not re-running the cryptographic check.

**What it flat out cannot catch:** zero day phishing kits that don't match
any of these seven patterns. An attacker who registers a domain months in
advance, lets it age past any "newly registered" threshold, writes calm
professional sounding copy with zero urgency language, and sends from a
domain with valid SPF and DKIM because they control it outright, is going
to sail right through this tool with a low score. Business email
compromise, where an attacker has actually taken over a legitimate mailbox
and sends from the real domain with real passing authentication, is
basically invisible to every signal here except maybe urgency language.
This tool checks for patterns, it does not understand intent, and a patient
attacker can avoid every pattern I coded for.

I'd treat this as one input into a decision, not the decision itself.

## One fact I didn't know until I started building this

DMARC (the protocol that ties SPF and DKIM together and tells a receiving
server what to do when they fail) exists partly because of PayPal. PayPal
was getting phished so heavily in the mid 2000s that they started working
with Yahoo on an authentication based blocking approach around 2006, and
that work eventually grew into the group of companies, PayPal included,
that organized DMARC.org and published the first DMARC spec in 2012. Which
makes it kind of fitting, and a little funny, that "a lookalike PayPal
domain with valid SPF" is one of my sample phishing emails.

## Project structure

```
phishing-analyzer/
  phishing_analyzer/
    __init__.py
    email_parser.py      parsing raw .eml bytes into structured data
    signals.py            the seven detection checks
    scorer.py              weights, thresholds, score calculation
    report.py              text and JSON report formatting
    cli.py                  argparse entry point
  tests/
    test_parser.py
    test_signals.py
    test_scorer.py
    sample_emails/          ten hand built .eml files
  .github/workflows/tests.yml
  conftest.py             empty, see note in Testing section below
  README.md
  LICENSE
  requirements.txt
  .gitignore
```

## License

MIT, see LICENSE.
