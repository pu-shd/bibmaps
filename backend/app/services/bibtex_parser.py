import bibtexparser
from bibtexparser import middlewares
from bibtexparser.model import DuplicateBlockKeyBlock
from pylatexenc.latex2text import LatexNodes2Text, get_default_latex_context_db
from typing import List, Dict, Tuple
import json


# LaTeX decoder that, like v1's convert_to_unicode, leaves typographic
# specials such as "--" in page ranges and ``quotes`` untouched.
_LATEX_DECODER = LatexNodes2Text(
    latex_context=get_default_latex_context_db().filter_context(
        exclude_categories=['nonascii-specials']
    ),
    math_mode='verbatim',
)


def _middlewares():
    """Middlewares replicating the v1 parser setup (lowercase field keys,
    common month strings, LaTeX to unicode)."""
    return [
        middlewares.NormalizeFieldKeys(),
        middlewares.MonthLongStringMiddleware(),
        middlewares.LatexDecodingMiddleware(decoder=_LATEX_DECODER),
    ]


def _entry_to_dict(entry) -> Dict:
    """Convert a v2 Entry into the v1-style dict used by parse_entry."""
    record = {'ID': entry.key, 'ENTRYTYPE': entry.entry_type.lower()}
    for field in entry.fields:
        record[field.key] = field.value
    return record


def parse_bibtex(bibtex_content: str) -> Tuple[List[Dict], List[str]]:
    """
    Parse BibTeX content and return list of parsed entries and any errors.

    Returns:
        Tuple of (entries, errors) where entries is a list of dicts and
        errors is a list of error messages
    """
    errors = []
    entries = []

    try:
        library = bibtexparser.parse_string(
            bibtex_content, append_middleware=_middlewares()
        )

        raw_entries = [(entry.start_line, entry) for entry in library.entries]
        for block in library.failed_blocks:
            if isinstance(block, DuplicateBlockKeyBlock):
                # v2 rejects duplicate keys; pass them through so the caller
                # reports them as skipped duplicates, as with v1.
                dup = bibtexparser.parse_string(
                    block.ignore_error_block.raw, append_middleware=_middlewares()
                )
                raw_entries.extend((block.start_line, e) for e in dup.entries)
            else:
                errors.append(
                    f"BibTeX parsing error at line {block.start_line + 1}: {block.error}"
                )

        raw_entries.sort(key=lambda pair: pair[0])
        for _, entry in raw_entries:
            parsed_entry = parse_entry(_entry_to_dict(entry))
            if parsed_entry:
                entries.append(parsed_entry)

    except Exception as e:
        errors.append(f"BibTeX parsing error: {str(e)}")

    return entries, errors


def parse_entry(entry: Dict) -> Dict:
    """Parse a single BibTeX entry into our schema format."""
    # Standard fields we track
    standard_fields = {
        'title', 'author', 'year', 'journal', 'booktitle',
        'publisher', 'volume', 'number', 'pages', 'doi',
        'url', 'abstract', 'ID', 'ENTRYTYPE'
    }

    # Extract standard fields
    parsed = {
        'bibtex_key': entry.get('ID', ''),
        'entry_type': entry.get('ENTRYTYPE', 'misc'),
        'title': entry.get('title'),
        'author': entry.get('author'),
        'year': entry.get('year'),
        'journal': entry.get('journal'),
        'booktitle': entry.get('booktitle'),
        'publisher': entry.get('publisher'),
        'volume': entry.get('volume'),
        'number': entry.get('number'),
        'pages': entry.get('pages'),
        'doi': entry.get('doi'),
        'url': entry.get('url'),
        'abstract': entry.get('abstract'),
    }

    # Collect extra fields
    extra_fields = {}
    for key, value in entry.items():
        if key not in standard_fields and value:
            extra_fields[key] = value

    if extra_fields:
        parsed['extra_fields'] = json.dumps(extra_fields)
    else:
        parsed['extra_fields'] = None

    # Generate raw BibTeX for this entry
    parsed['raw_bibtex'] = generate_bibtex_entry(entry)

    return parsed


def generate_bibtex_entry(entry: Dict) -> str:
    """Generate BibTeX string from entry dict."""
    entry_type = entry.get('ENTRYTYPE', 'misc')
    key = entry.get('ID', 'unknown')

    lines = [f"@{entry_type}{{{key},"]

    for field, value in entry.items():
        if field not in ('ENTRYTYPE', 'ID') and value:
            # Escape special characters and format
            clean_value = str(value).replace('{', '').replace('}', '')
            lines.append(f"  {field} = {{{clean_value}}},")

    lines.append("}")
    return "\n".join(lines)


def format_reference_citation(reference) -> str:
    """Format a reference for display as a citation."""
    parts = []

    if reference.author:
        parts.append(reference.author)

    if reference.year:
        parts.append(f"({reference.year})")

    if reference.title:
        parts.append(f'"{reference.title}"')

    if reference.journal:
        parts.append(f"<em>{reference.journal}</em>")
    elif reference.booktitle:
        parts.append(f"In <em>{reference.booktitle}</em>")

    if reference.volume:
        vol_str = reference.volume
        if reference.number:
            vol_str += f"({reference.number})"
        parts.append(vol_str)

    if reference.pages:
        parts.append(f"pp. {reference.pages}")

    if reference.publisher:
        parts.append(reference.publisher)

    return ", ".join(parts) + "."
