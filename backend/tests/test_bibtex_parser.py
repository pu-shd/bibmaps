"""Unit tests for the BibTeX parsing service."""
import json

from app.services.bibtex_parser import parse_bibtex


def test_parses_standard_fields():
    entries, errors = parse_bibtex(
        "@article{smith2020, title={Deep Learning}, author={Smith, J. and Doe, A.},"
        " journal={Nature}, year={2020}, volume={5}, number={2}, pages={1--10},"
        " doi={10.1000/xyz}}"
    )
    assert errors == []
    assert len(entries) == 1
    e = entries[0]
    assert e["bibtex_key"] == "smith2020"
    assert e["entry_type"] == "article"
    assert e["title"] == "Deep Learning"
    assert e["author"] == "Smith, J. and Doe, A."
    assert e["journal"] == "Nature"
    assert e["year"] == "2020"
    assert e["volume"] == "5"
    assert e["number"] == "2"
    assert e["pages"] == "1--10"
    assert e["doi"] == "10.1000/xyz"
    assert e["extra_fields"] is None
    assert e["raw_bibtex"].startswith("@article{smith2020,")


def test_field_keys_and_entry_type_are_lowercased():
    entries, errors = parse_bibtex("@ARTICLE{k, Title={Upper}, YEAR={2021}}")
    assert errors == []
    assert entries[0]["entry_type"] == "article"
    assert entries[0]["title"] == "Upper"
    assert entries[0]["year"] == "2021"


def test_latex_is_converted_to_unicode():
    entries, errors = parse_bibtex(r'@misc{k, title={M\"uller and {GPU}s}}')
    assert errors == []
    assert entries[0]["title"] == "Müller and GPUs"


def test_month_abbreviation_and_string_macros_resolve():
    entries, errors = parse_bibtex(
        '@string{nat = "Nature"}\n@article{k, journal=nat, month=feb, note={n}}'
    )
    assert errors == []
    assert entries[0]["journal"] == "Nature"
    extra = json.loads(entries[0]["extra_fields"])
    assert extra == {"month": "February", "note": "n"}


def test_multiple_entries_keep_order():
    entries, errors = parse_bibtex(
        "@article{a, title={A}}\n@book{b, title={B}, publisher={P}}\n@misc{c, title={C}}"
    )
    assert errors == []
    assert [e["bibtex_key"] for e in entries] == ["a", "b", "c"]
    assert entries[1]["publisher"] == "P"


def test_duplicate_keys_are_passed_through_in_order():
    entries, errors = parse_bibtex(
        "@article{k, title={First}}\n@misc{other, title={O}}\n@article{k, title={Second}}"
    )
    assert errors == []
    assert [(e["bibtex_key"], e["title"]) for e in entries] == [
        ("k", "First"), ("other", "O"), ("k", "Second")
    ]


def test_malformed_block_reports_error_and_keeps_valid_entries():
    entries, errors = parse_bibtex("@article{ok, title={Fine}}\n@book{bad, title={unclosed\n")
    assert [e["bibtex_key"] for e in entries] == ["ok"]
    assert len(errors) == 1
    assert errors[0].startswith("BibTeX parsing error")


def test_empty_input_yields_nothing():
    assert parse_bibtex("") == ([], [])
