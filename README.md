# phishnet

A command line tool that takes a raw `.eml` file and scores how likely it
is to be phishing. Working on this as a portfolio project while finishing
my master's in cybersecurity management.

Status so far: the parser is working, it pulls headers, body text, links,
and attachments out of a raw `.eml` file. Detection signals (SPF/DKIM/DMARC
checks, suspicious links, urgency language, and a few others) are next.

More to come.
