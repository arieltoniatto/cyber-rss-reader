"""Normalize public CVE JSON 5 records without inferring exposure or exploitability."""
from __future__ import annotations

import re
from urllib.parse import urlsplit
from parser.models import Article, IOCType

_ID = re.compile(r'CVE-[0-9]{4}-[0-9]{4,19}', re.IGNORECASE)
_MENTION = re.compile(r'(?<![\w-])CVE-[0-9]{4}-[0-9]{4,19}(?![\w-])', re.IGNORECASE)


def normalize_cve(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value.strip()):
        raise ValueError('Use a CVE identifier such as CVE-2021-44228.')
    return value.strip().upper()


def article_cves(article: Article) -> list[str]:
    candidates = [*article.cve_ids, *(ioc.value for ioc in article.iocs if ioc.type == IOCType.CVE)]
    text = '\n'.join([article.title, article.summary, *article.tags])
    candidates.extend(match.group() for match in _MENTION.finditer(text))
    identifiers = set()
    for candidate in candidates:
        try:
            identifiers.add(normalize_cve(candidate))
        except ValueError:
            continue
    return sorted(identifiers)


def _text(value, limit=12000):
    return value[:limit] if isinstance(value, str) else ''


def _items(value):
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _description(values):
    rows = _items(values)
    preferred = next((r for r in rows if str(r.get('lang', '')).lower().startswith('en')), None)
    return _text((preferred or (rows[0] if rows else {})).get('value'))


def safe_reference(value):
    if not isinstance(value, str) or len(value) > 2048 or any(c.isspace() for c in value) or '\\' in value:
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme in ('http', 'https') and parts.hostname and not parts.username and not parts.password:
            parts.port  # Validate malformed ports.
            return value
    except ValueError:
        pass
    return None


def normalize_record(payload, expected_id: str) -> dict:
    expected_id = normalize_cve(expected_id)
    if not isinstance(payload, dict) or payload.get('dataType') != 'CVE_RECORD':
        raise ValueError('Invalid CVE record')
    metadata = payload.get('cveMetadata')
    containers = payload.get('containers')
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        raise ValueError('Invalid CVE metadata')
    if metadata.get('cveId') != expected_id or metadata.get('state') not in ('PUBLISHED', 'REJECTED'):
        raise ValueError('Unexpected CVE identifier or state')
    cna = containers.get('cna')
    if not isinstance(cna, dict):
        raise ValueError('Missing CNA container')
    state = metadata['state']
    record = {'cve_id': expected_id, 'state': state, 'title': _text(cna.get('title'), 1000),
              'description': _description(cna.get('rejectedReasons') if state == 'REJECTED' else cna.get('descriptions')),
              'published': _text(metadata.get('datePublished'), 80),
              'updated': _text(metadata.get('dateUpdated'), 80),
              'source': 'CVE Program', 'source_url': 'https://www.cve.org/CVERecord?id=' + expected_id,
              'cvss': [], 'cwes': [], 'affected': [], 'references': []}
    if state == 'REJECTED':
        return record  # Rejected identifiers must not retain active vulnerability details.
    refs, cwes = set(), set()
    for container in [cna, *_items(containers.get('adp'))]:
        provider = container.get('providerMetadata')
        provider = provider if isinstance(provider, dict) else {}
        source = _text(provider.get('shortName') or provider.get('orgId'), 200) or ('CNA' if container is cna else 'ADP')
        for metric in _items(container.get('metrics')):
            for key in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0', 'cvssV2_0'):
                cvss = metric.get(key)
                if not isinstance(cvss, dict):
                    continue
                score = cvss.get('baseScore')
                version = {'cvssV4_0': '4.0', 'cvssV3_1': '3.1', 'cvssV3_0': '3.0', 'cvssV2_0': '2.0'}[key]
                vector = _text(cvss.get('vectorString'), 500)
                if type(score) not in (int, float) or not 0 <= score <= 10 or not vector:
                    continue
                severity = ('LOW' if score < 4 else 'MEDIUM' if score < 7 else 'HIGH') if version == '2.0' else (
                    'NONE' if score == 0 else 'LOW' if score < 4 else 'MEDIUM' if score < 7 else 'HIGH' if score < 9 else 'CRITICAL')
                item = {'version': version, 'score': score, 'severity': severity, 'vector': vector, 'source': source}
                if item not in record['cvss']:
                    record['cvss'].append(item)
        for problem in _items(container.get('problemTypes')):
            for description in _items(problem.get('descriptions')):
                identifier = description.get('cweId')
                if isinstance(identifier, str) and re.fullmatch(r'CWE-[0-9]+', identifier):
                    cwes.add(identifier)
        for reference in _items(container.get('references')):
            if value := safe_reference(reference.get('url')):
                refs.add(value)
    for product in _items(cna.get('affected'))[:100]:
        versions = []
        for version in _items(product.get('versions'))[:100]:
            row = {key: _text(version.get(key), 300) for key in ('version', 'status', 'lessThan', 'lessThanOrEqual', 'versionType')
                   if isinstance(version.get(key), str)}
            # Preserve conditional status changes instead of flattening ranges.
            changes = [{key: _text(change.get(key), 300) for key in ('at', 'status') if isinstance(change.get(key), str)}
                       for change in _items(version.get('changes'))[:100]]
            if changes:
                row['changes'] = changes
            if row:
                versions.append(row)
        record['affected'].append({'vendor': _text(product.get('vendor'), 300), 'product': _text(product.get('product'), 300),
                                   'default_status': _text(product.get('defaultStatus'), 80), 'versions': versions})
    record['cwes'] = sorted(cwes)
    record['references'] = sorted(refs)[:100]
    return record
