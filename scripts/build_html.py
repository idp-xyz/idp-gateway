#!/usr/bin/env python3
"""Regenerate the HTML mirrors of the Markdown documents.

Markdown is the source; the HTML pages are derived and must not be edited by hand inside
an article body or a sidebar. Every page is a hand-made shell (header, footer, styles)
around a body rendered from one Markdown file. This script re-renders the bodies and the
sidebar navigation and leaves the rest of each shell exactly as it is, so it never
redesigns a page. A page that does not exist yet is created with a plain shell. The
offline reader is one shell around several bodies, with images inlined and links pointed
at its own sections.

Rendering is what produced the delivered pages: python-markdown with tables and fenced
code, sequential heading ids (h-1, h-2, ...), and links to mirrored .md files turned into
links to their .html pages.

index.html has no Markdown source: only its sidebar is generated here.
portal/prototypes/ is not touched.

Usage:  .venv/bin/python scripts/build_html.py           rewrite whatever is out of date
        .venv/bin/python scripts/build_html.py --check   list what is out of date, exit 1 if anything is
"""
from __future__ import annotations
import argparse, base64, html, posixpath, re, sys
from pathlib import Path

import markdown
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
ADRS = sorted(p.stem for p in (ROOT / 'decisions').glob('ADR-*.md'))

# Markdown source -> HTML mirror. To mirror another document, add a line; the page is created on the next run.
PAGES = {
    'docs/G01_Requirements.md': 'docs/G01_Requirements.html',
    'docs/G02_Architecture.md': 'docs/G02_Architecture.html',
    'docs/G03_Routing_and_Configuration.md': 'docs/G03_Routing_and_Configuration.html',
    'docs/G04_Identity_and_Security.md': 'docs/G04_Identity_and_Security.html',
    'docs/G05_Engineering_and_Operations.md': 'docs/G05_Engineering_and_Operations.html',
    'docs/G06_Testing_and_Acceptance.md': 'docs/G06_Testing_and_Acceptance.html',
    'portal/spec/Gateway_Operations_UX_Spec_V1.0.md': 'portal/spec/Gateway_Operations_UX_Spec_V1.0.html',
    'portal/spec/Agentgateway_UI_Capability_Matrix_V1.0.md': 'portal/spec/Agentgateway_UI_Capability_Matrix_V1.0.html',
    'poc/p1/README.md': 'poc/p1/README.html',
    'decisions/README.md': 'decisions/README.html',
    **{f'decisions/{adr}.md': f'decisions/{adr}.html' for adr in ADRS},
}
# Pages without a Markdown source whose sidebar is still generated.
SIDEBAR_ONLY = ['index.html']

# The sidebar of every page that has one: (group title, [(number badge or None, label, target page)]).
NAV = [
    ('ENGINEERING BASELINE', [
        ('G01', '产品需求与范围', 'docs/G01_Requirements.html'),
        ('G02', '系统架构与 DDD 边界', 'docs/G02_Architecture.html'),
        ('G03', '路由与配置治理', 'docs/G03_Routing_and_Configuration.html'),
        ('G04', '认证鉴权与凭证安全', 'docs/G04_Identity_and_Security.html'),
        ('G05', 'Go 工程与运维', 'docs/G05_Engineering_and_Operations.html'),
        ('G06', '测试与验收', 'docs/G06_Testing_and_Acceptance.html'),
    ]),
    ('POC & DECISIONS', [
        (None, 'P1 PoC 报告', 'poc/p1/README.html'),
        (None, 'ADR 决策记录', 'decisions/README.html'),
    ]),
    ('GATEWAY OPERATIONS', [
        (None, '18 页交互式 UI / UX 原型', 'portal/prototypes/gateway-operations.html'),
    ]),
]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding='utf-8')


def title_of(source: str) -> str:
    """Text of the first heading of a Markdown file."""
    return read(source).lstrip().splitlines()[0].lstrip('# ').strip()


READER = 'IDP_Gateway_V1.0_Offline_Reader.html'
# (anchor id, label in the reader's navigation, line above the section, Markdown source)
READER_SECTIONS = [
    ('g01', 'G01 · 产品需求与范围', 'G01 / 需求与目标', 'docs/G01_Requirements.md'),
    ('g02', 'G02 · 系统架构与 DDD 边界', 'G02 / 系统与领域', 'docs/G02_Architecture.md'),
    ('g03', 'G03 · 路由与配置治理', 'G03 / 运行时发布', 'docs/G03_Routing_and_Configuration.md'),
    ('g04', 'G04 · 认证鉴权与凭证安全', 'G04 / 信任与安全', 'docs/G04_Identity_and_Security.md'),
    ('g05', 'G05 · Go 工程与运维', 'G05 / 工程实施', 'docs/G05_Engineering_and_Operations.md'),
    ('g06', 'G06 · 测试与验收', 'G06 / 验证与交付', 'docs/G06_Testing_and_Acceptance.md'),
    ('poc-p1', 'P1 PoC · 凭证注入实测', 'POC P1 / 概念验证，非验收', 'poc/p1/README.md'),
    *[(adr.lower(), title_of(f'decisions/{adr}.md').replace(' — ', ' · '), f'{adr} / 架构决策', f'decisions/{adr}.md')
      for adr in ADRS],
]
READER_ANCHOR = {md: sid for sid, _, _, md in READER_SECTIONS}

ARTICLE_OPEN, ARTICLE_CLOSE = '<article class="article">', '</article>'
SECTION_OPEN = '<section class="reader-section"'
SIDEBAR = re.compile(r'<aside class="sidebar">.*?</aside>', re.S)
IMAGE_TYPES = {'.svg': 'image/svg+xml', '.png': 'image/png'}
EXTERNAL = re.compile(r'^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//|#)')

NEW_PAGE = ('<!doctype html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,'
            'initial-scale=1"><meta name="color-scheme" content="light"><title>{title} | IDP Gateway V1.0</title>'
            '<link rel="stylesheet" href="{up}assets/site.css"></head><body><header class="site-header">'
            '<a class="brand" href="{up}index.html"><span class="brand-mark">IDP</span> IDP GATEWAY '
            '<span style="color:#99aab8">/</span> Engineering Baseline</a><div class="header-meta">V1.0 · DESIGN DRAFT · '
            '2026-11-10</div><span class="pill warn">NOT PRODUCTION APPROVED</span></header><div class="layout">'
            '<aside class="sidebar"></aside><main class="page"><div class="topline">{topline}</div>'
            + ARTICLE_OPEN + '{body}' + ARTICLE_CLOSE +
            '<div class="doc-footer-nav"><a href="{up}index.html">← 文档总览</a></div>'
            '<div class="footer">IDP Gateway V1.0 · 设计候选 · 文件可离线阅读 · 正式验收 / 审批 / 生产验证尚未完成</div>'
            '</main></div></body></html>\n')


def sidebar(page: str) -> str:
    here = posixpath.dirname(page) or '.'

    def item(number, label, target):
        # A README page stands for its whole directory: "ADR 决策记录" stays lit on every ADR page.
        active = page == target or (posixpath.basename(target) == 'README.html'
                                    and posixpath.dirname(page) == posixpath.dirname(target))
        badge = f'<span class="num">{number}</span> ' if number else ''
        return (f'<a class="nav-item{" active" if active else ""}" href="{posixpath.relpath(target, here)}">'
                f'{badge}{html.escape(label)}</a>')

    groups = [f'<div class="aside-title">{html.escape(title)}</div>' + ''.join(item(*i) for i in items)
              for title, items in NAV]
    return ('<aside class="sidebar">' + '<hr class="aside-sep">'.join(groups) + '<hr class="aside-sep">'
            f'<a class="nav-item" href="{posixpath.relpath("index.html", here)}">← 总览 / Overview</a>'
            '<div class="aside-title">CURRENT STATUS</div><div class="pill plain">Runtime tests NOT_RUN</div></aside>')


def with_sidebar(text: str, page: str) -> str:
    """`text` with its sidebar, if it has one, replaced by the current navigation."""
    return SIDEBAR.sub(lambda _: sidebar(page), text, count=1)


def relink(href: str, source_dir: str, page: str) -> str:
    """Where a relative link written in a Markdown file under source_dir must point when it sits in `page`."""
    if EXTERNAL.match(href):
        return href
    path, _, fragment = href.partition('#')
    target = posixpath.normpath(posixpath.join(source_dir, path))      # repository-relative
    if page == READER and target in READER_ANCHOR:
        return '#' + READER_ANCHOR[target]
    target = PAGES.get(target, target)
    return posixpath.relpath(target, posixpath.dirname(page) or '.') + ('#' + fragment if fragment else '')


def render(source: str, page: str) -> str:
    """Body HTML of Markdown file `source` as it appears inside `page` (both repository-relative)."""
    soup = BeautifulSoup(markdown.markdown(read(source), extensions=['tables', 'fenced_code']), 'html.parser')
    for n, heading in enumerate(soup.find_all(re.compile(r'^h[1-6]$')), 1):
        heading['id'] = f'h-{n}'
    source_dir = posixpath.dirname(source)
    for a in soup.find_all('a', href=True):
        a['href'] = relink(a['href'], source_dir, page)
    for img in soup.find_all('img', src=True):
        if EXTERNAL.match(img['src']):
            continue
        target = posixpath.normpath(posixpath.join(source_dir, img['src']))
        if page == READER:                                              # single file: inline the image
            kind = IMAGE_TYPES[posixpath.splitext(target)[1].lower()]
            img['src'] = f'data:{kind};base64,' + base64.b64encode((ROOT / target).read_bytes()).decode('ascii')
        else:
            img['src'] = posixpath.relpath(target, posixpath.dirname(page) or '.')
    return str(soup) + '\n'


def build_page(source: str, page: str) -> str:
    body = render(source, page)
    if (ROOT / page).is_file():
        shell = read(page)
    else:
        shell = NEW_PAGE.format(title=html.escape(title_of(source)), up='../' * page.count('/'), body='',
                                topline=html.escape(' / '.join(Path(source).with_suffix('').parts).upper()))
    opener, closer = (ARTICLE_OPEN, ARTICLE_CLOSE) if ARTICLE_OPEN in shell else ('<body>', '</body>')
    if shell.count(opener) != 1:
        raise SystemExit(f'{page}: expected exactly one {opener}')
    head, rest = shell.split(opener, 1)
    tail = rest.rsplit(closer, 1)[1]
    return with_sidebar(head, page) + opener + body + closer + tail


def build_reader() -> str:
    shell = read(READER)
    start, end = shell.index(SECTION_OPEN), shell.rindex('<div class="footer">')
    sections = ''.join(f'{SECTION_OPEN} id="{sid}"><div class="topline">{html.escape(topline)}</div>'
                       f'{ARTICLE_OPEN}{render(source, READER)}{ARTICLE_CLOSE}</section>'
                       for sid, _, topline, source in READER_SECTIONS)
    nav = '<div class="reader-nav">' + ''.join(f'<a href="#{sid}">{html.escape(label)}</a>'
                                               for sid, label, _, _ in READER_SECTIONS) + '</div>'
    head, count = re.subn(r'<div class="reader-nav">.*?</div>', lambda _: nav, shell[:start], count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f'{READER}: navigation block not found')
    return head + sections + shell[end:]


def build_all() -> dict[str, str]:
    """page path -> content it should have."""
    out = {page: build_page(source, page) for source, page in PAGES.items()}
    out.update({page: with_sidebar(read(page), page) for page in SIDEBAR_ONLY})
    out[READER] = build_reader()
    return out


def out_of_date() -> list[str]:
    return [page for page, content in build_all().items()
            if not (ROOT / page).is_file() or read(page) != content]


def main() -> int:
    ap = argparse.ArgumentParser(description='Regenerate the HTML mirrors of the Markdown documents')
    ap.add_argument('--check', action='store_true', help='write nothing; exit 1 if any page is out of date')
    args = ap.parse_args()
    built = build_all()
    stale = [page for page, content in built.items() if not (ROOT / page).is_file() or read(page) != content]
    for page in stale:
        if not args.check:
            (ROOT / page).write_text(built[page], encoding='utf-8')
        print(('out of date: ' if args.check else 'wrote: ') + page)
    print(f'{len(built) - len(stale)} of {len(built)} pages already current' if stale or args.check else f'all {len(built)} pages current')
    return 1 if args.check and stale else 0


if __name__ == '__main__':
    sys.exit(main())
