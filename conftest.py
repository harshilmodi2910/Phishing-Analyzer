# This file is empty on purpose. Having a conftest.py at the project root
# is what makes `pytest` work when you run it as a bare command instead of
# `python -m pytest`. Without it, pytest doesn't put the project root on
# sys.path, so tests/test_parser.py can't find the phishing_analyzer
# package and fails with ModuleNotFoundError. Found this the hard way.
