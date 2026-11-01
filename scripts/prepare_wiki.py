"""Prepare tracked documentation for GitHub Wiki; never commits or publishes."""
import argparse
from pathlib import Path
import re


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True,
                        help='Destination for managed Markdown pages; existing page filenames are overwritten')
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / 'docs' / 'wiki'
    destination = args.output.resolve()
    if destination == source.resolve():
        parser.error('output must differ from the tracked Wiki source')
    pages = sorted(source.glob('*.md'))
    names = {page.name for page in pages}
    if 'Home.md' not in names:
        parser.error('Wiki source is missing Home.md')

    def wiki_link(match):
        filename, fragment = match.group(1), match.group(2) or ''
        if filename not in names:
            parser.error('Wiki link points to a missing page: ' + filename)
        return '](' + filename[:-3] + fragment + ')'

    prepared = {}
    for page in pages:
        prepared[page.name] = re.sub(r'\]\(([A-Za-z0-9_-]+\.md)(#[^)]*)?\)',
                                     wiki_link, page.read_text(encoding='utf-8'))
    destination.mkdir(parents=True, exist_ok=True)
    for name, content in prepared.items():
        (destination / name).write_text(content, encoding='utf-8')
    print(f'Prepared {len(prepared)} Markdown files in {destination}; nothing published')


if __name__ == '__main__':
    main()
