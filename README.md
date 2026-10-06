# phishnet

A command line tool that takes a raw `.eml` file and scores how likely it
is to be phishing. Built this as a portfolio project for my cybersecurity
master's, wanted something that actually broke the decision down into
separate checks instead of just vibes.

Not a spam filter, doesn't catch everything. Limitations section below is
worth reading before you trust this on a real inbox.

## What it does

Give it a `.eml` file. It parses the headers and body, runs seven checks,
and spits out a score from 0 to 100 plus a low/medium/high label. Checks
can trigger partially, not just on or off.

The seven checks, roughly in order of how much weight they carry:

Authentication (SPF, DKIM, DMARC, read from the `Authentication-Results`
header, missing header counts against it too), suspicious links (URL
shorteners, display text that doesn't match where the link actually goes,
domains that look like a misspelled brand name), spoofed display names
(says PayPal, sends from somewhere that has nothing to do with PayPal),
attachment flags (exe/script attachments, the invoice.pdf.exe double
extension trick), newly registered domains, reply-to mismatches, and
urgency language in the body ("act now," "your account will be
suspended," that kind of thing). Domain age is the one with the weirder
implementation, see the design note further down.

## Installation

```bash
git clone https://github.com/harshilmodi2910/phishnet.git
cd phishnet
pip install -r requirements.txt
```

Only needs the standard library really. `python-whois` in
requirements.txt is optional, enables a live domain age lookup, tool
works fine without it.

## Usage

```bash
python -m phishing_analyzer.cli --file sample.eml
python -m phishing_analyzer.cli --file sample.eml --json-out report.json
python -m phishing_analyzer.cli --batch tests/sample_emails/
```

Also added `--verbose` (prints the detail lines under each signal),
`--quiet` (no terminal output, useful if you just want the JSON file),
and `--weights-config path.json` to override the default weights without
touching code.

Sample output:

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

## Scoring

| signal | weight |
|---|---|
| authentication | 22 |
| suspicious_links | 20 |
| spoofed_display_name | 17 |
| attachment_flags | 15 |
| newly_registered_domain | 10 |
| reply_to_mismatch | 8 |
| urgency_language | 8 |

Adds up to 100. I picked these numbers based on gut feel about which
signals matter more, not off any real dataset, I don't have one.
Authentication got the highest weight since SPF/DKIM/DMARC are at least
technically checkable, urgency language got the lowest since an attacker
can just not write "act now" and skip right past it. If you disagree,
that's the point of `--weights-config`, write your own.

Risk labels: 0-29 low, 30-59 medium, 60+ high. Same deal, not calibrated
against anything, just felt like reasonable cutoffs.

## Sample data

Ten hand written `.eml` files in `tests/sample_emails/`, mix of clean and
phishing, each built to isolate a combination of signals. A couple clean
ones, one where SPF fails but the links are fine, one with a lookalike
paypa1.com domain that actually has valid SPF since the attacker owns the
domain outright, one with urgency language and a shortened link but
passing auth, one impersonating Bank of America, the double extension
attachment trick, a reply-to mismatch, and one that just piles on every
signal at once and scores 83.

None of these are real emails. I made them up. The "attachments" are fake
bytes, not actual executables.

## Testing

```bash
pytest tests/ -v
```

63 tests, split across parsing, the seven signals (each tested in
isolation with small hand built email objects), and the scoring math.

GitHub Actions runs it on push against Python 3.10-3.12.

Side note: there's an empty `conftest.py` in the root. Without it,
running plain `pytest` (not `python -m pytest`) fails with
ModuleNotFoundError because pytest doesn't put the project root on
sys.path by itself. Took me a bit to figure out why that was happening.

## Why not just do live WHOIS lookups

Wanted real WHOIS data for the domain age check at first, since "how old
is this domain" is a genuinely good signal. Then I actually tried it and
WHOIS servers rate limit fast, privacy proxy registrations give you the
proxy's creation date instead of the real one half the time, and the
whole thing just breaks on a machine with no outbound network access,
which is a real possibility for something other people are going to
clone and run. So now it tries live WHOIS if `python-whois` is installed
and returns something usable, and falls back to checking the TLD
(.tk, .xyz, .top and the usual suspects) plus some basic shape checks on
the domain name if that fails. Worse than real WHOIS data, I know, but it
degrades instead of just not working. Not totally sold this was the
right call honestly, a stricter approach might say a bad signal is worse
than no signal, but it still catches the obvious garbage domains.

## Limitations

Being honest about this since I'd want to know if I were relying on it.
False positives are a real risk, a legit company with a DNS
misconfiguration fails SPF the same way an attacker would, and normal
marketing copy trips the urgency check all the time. No allowlisting
built in for known-good domains, felt out of scope here.

The authentication check also just trusts the `Authentication-Results`
header, meaning it trusts whatever mail server added it. It can't
re-verify SPF or DKIM on its own, it's reading a claim. And none of this
catches a patient attacker: a domain aged past the threshold, calm
professional copy with no urgency language, valid SPF and DKIM because
they own the domain outright, that sails through with a low score.
Business email compromise (an attacker actually inside a real mailbox,
sending from the real domain with real passing auth) is basically
invisible here. This checks for patterns, not intent.

## A fact I didn't know before this project

DMARC exists partly because of PayPal, they got phished so badly in the
mid 2000s that they started working with Yahoo on it around 2006, which
eventually turned into the group that published the first DMARC spec in
2012. Kind of funny that a lookalike PayPal domain ended up as one of my
sample emails.

## Project structure

```
phishing-analyzer/
  phishing_analyzer/
    __init__.py
    email_parser.py
    signals.py
    scorer.py
    report.py
    cli.py
  tests/
    test_parser.py
    test_signals.py
    test_scorer.py
    sample_emails/
  .github/workflows/tests.yml
  conftest.py
  README.md
  LICENSE
  requirements.txt
  .gitignore
```

## License

MIT, see LICENSE.
