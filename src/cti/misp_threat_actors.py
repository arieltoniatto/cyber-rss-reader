"""Conservative MISP Galaxy name/alias integration; no inferred ATT&CK relationships."""
from __future__ import annotations

from collections import defaultdict
import re
from urllib.parse import urlsplit
from uuid import UUID

GALAXY_UUID = '7cdff317-a673-4474-84ec-4f1754947823'
SOURCE_URL = 'https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json'
_GENERIC = {'unknown', 'unknown actor', 'unknown group', 'group', 'threat actor', 'apt', 'adversary',
            'ransomware', 'hackers', 'hacker', 'attacker', 'actor', 'attack', 'malware', 'campaign', 'operation', 'team', 'none', 'n/a'}


def validate_galaxy(payload):
    if (not isinstance(payload, dict) or payload.get('type') != 'threat-actor'
            or payload.get('uuid') != GALAXY_UUID or type(payload.get('version')) is not int
            or payload['version'] < 1 or not isinstance(payload.get('values'), list) or not payload['values']):
        raise ValueError('Invalid MISP Threat Actor Galaxy')
    seen = set()
    for row in payload['values']:
        if not isinstance(row, dict) or not isinstance(row.get('value'), str) or not row['value'].strip():
            raise ValueError('Invalid MISP actor name')
        identifier = row.get('uuid')
        if not isinstance(identifier, str):
            raise ValueError('Missing MISP cluster UUID')
        UUID(identifier)
        if identifier in seen:
            raise ValueError('Duplicate MISP cluster UUID')
        seen.add(identifier)
        meta = row.get('meta', {})
        if not isinstance(meta, dict) or not isinstance(meta.get('synonyms', []), list):
            raise ValueError('Invalid MISP actor metadata')
        for key in ('refs', 'threat-actor-classification'):
            if key in meta and (not isinstance(meta[key], list) or any(not isinstance(value, str) for value in meta[key])):
                raise ValueError('Invalid MISP actor metadata list')
        if any(not isinstance(alias, str) for alias in meta.get('synonyms', [])):
            raise ValueError('Invalid MISP synonym')
    return payload


def _name(value):
    return ' '.join(value.split()) if isinstance(value, str) else ''


def _group_ids(row):
    identifiers = {alias for alias in row.get('meta', {}).get('synonyms', []) if re.fullmatch(r'G[0-9]{4}', alias)}
    for value in row.get('meta', {}).get('refs', []):
        if not isinstance(value, str):
            continue
        try:
            parts = urlsplit(value)
        except ValueError:
            continue
        match = re.fullmatch(r'/groups/(G[0-9]{4})/?', parts.path)
        if parts.scheme == 'https' and parts.netloc == 'attack.mitre.org' and match:
            identifiers.add(match[1])
    return identifiers


def requires_context(alias):
    # Single-word imports are not distinctive enough to detect in ordinary prose.
    return len(alias) < 5 or bool(re.fullmatch(r'(?:group|team)\s*[0-9]+', alias, re.I)) or (not re.search(r'[\s-]', alias) and not re.fullmatch(r'(?:APT|UNC|TA|UAC)[0-9]{2,}', alias, re.I))


def merge_actors(actors: list[dict], galaxy: dict, overrides: dict | None = None):
    validate_galaxy(galaxy)
    combined = [{'name': actor['name'], 'aliases': list(actor.get('aliases', []))} for actor in actors]
    aliases, canonical, group_ids = defaultdict(set), defaultdict(set), defaultdict(set)
    for index, actor in enumerate(actors):
        canonical[_name(actor['name']).casefold()].add(index)
        if isinstance(actor.get('attack_id'), str):
            group_ids[actor['attack_id']].add(index)
        for alias in [actor['name'], *actor.get('aliases', [])]:
            if name := _name(alias):
                aliases[name.casefold()].add(index)
    blocked = defaultdict(set)
    if isinstance(overrides, dict) and isinstance(overrides.get('actors'), list):
        for entry in overrides['actors']:
            if not isinstance(entry, dict):
                continue
            targets = group_ids.get(entry.get('attack_id'), set())
            for index, actor in enumerate(actors):
                if entry.get('stix_id') == actor.get('stix_id') and actor.get('stix_id'):
                    targets = targets | {index}
            for index in targets:
                blocked[index].update(_name(alias).casefold() for alias in entry.get('remove_aliases', []) if isinstance(alias, str))
    guarded = set()
    for row in galaxy['values']:
        meta = row.get('meta', {})
        classification = meta.get('threat-actor-classification', [])
        if isinstance(classification, list) and {'campaign', 'operation'}.intersection(classification):
            continue
        name = _name(row['value'])
        if name.casefold() in _GENERIC:
            continue
        candidates = set().union(*(group_ids.get(identifier, set()) for identifier in _group_ids(row)))
        direct = canonical.get(name.casefold(), set()) or aliases.get(name.casefold(), set())
        if candidates and direct and not direct.issubset(candidates):
            continue  # Conflicting explicit crosswalk: do not import aliases.
        if len(candidates) > 1:
            continue
        if not candidates:
            candidates = direct
        if len(candidates) > 1:
            continue
        if not candidates:
            # Identity resolution uses all meaningful synonyms; never take the first match.
            candidates = set().union(*(aliases.get(_name(alias).casefold(), set())
                                       for alias in meta.get('synonyms', []) if not requires_context(_name(alias))))
        if len(candidates) > 1:
            continue
        if candidates:
            target = next(iter(candidates))
        else:
            target = len(combined)
            combined.append({'name': name, 'aliases': [], 'misp_uuid': row['uuid']})
        owner = combined[target]['name']
        existing = {_name(alias).casefold() for alias in [owner, *combined[target]['aliases']]}
        for raw in [name, *meta.get('synonyms', [])]:
            alias = _name(raw)
            if not alias or alias.casefold() in _GENERIC or alias.casefold() in blocked[target]:
                continue
            # A cross-source alias cannot claim another MITRE canonical name.
            if canonical.get(alias.casefold(), set()) - {target}:
                continue
            original_owners = aliases.get(alias.casefold(), set())
            if len(original_owners) == 1 and original_owners != {target}:
                continue  # Preserve an existing unambiguous MITRE alias over a conflicting import.
            if alias.casefold() not in existing:
                combined[target]['aliases'].append(alias)
                existing.add(alias.casefold())
                if requires_context(alias):
                    guarded.add((owner, alias.casefold()))
        if target >= len(actors) and requires_context(owner):
            guarded.add((owner, owner.casefold()))
    return combined, guarded
