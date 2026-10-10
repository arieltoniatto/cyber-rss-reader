"""Compact, versioned Enterprise ATT&CK graph and article-context expansion."""
from collections import defaultdict
import json
import logging
from pathlib import Path
import re

from enrichment.text import mask_references, refang
from parser.models import Article, AttackMapping

logger = logging.getLogger(__name__)
_ID_PATTERNS = {
    'attack-pattern': r'T[0-9]{4}(?:\.[0-9]{3})?',
    'campaign': r'C[0-9]{4}', 'intrusion-set': r'G[0-9]{4}',
    'malware': r'S[0-9]{4}', 'tool': r'S[0-9]{4}',
}
_PAIRS = {
    'uses': {('intrusion-set', 'attack-pattern'), ('intrusion-set', 'malware'),
             ('intrusion-set', 'tool'), ('campaign', 'attack-pattern'), ('campaign', 'malware'),
             ('campaign', 'tool'), ('malware', 'attack-pattern'), ('tool', 'attack-pattern')},
    'attributed-to': {('campaign', 'intrusion-set')},
    'subtechnique-of': {('attack-pattern', 'attack-pattern')},
}
_IDS = re.compile(r'(?<![\w-])(?:T[0-9]{4}(?:\.[0-9]{3})?|[CSG][0-9]{4})(?![\w-]|\.[\w.])', re.IGNORECASE)


def _strings(value):
    return sorted({item.strip() for item in value if isinstance(item, str) and item.strip()}) if isinstance(value, list) else []


def _attack_id(obj):
    references = obj.get('external_references', [])
    if not isinstance(references, list):
        return None
    for ref in references:
        if isinstance(ref, dict) and ref.get('source_name') == 'mitre-attack':
            value = ref.get('external_id')
            if isinstance(value, str) and re.fullmatch(_ID_PATTERNS.get(obj.get('type'), r'(?!)'), value):
                return value
    return None


def attack_url(kind, attack_id):
    section = {'attack-pattern': 'techniques', 'campaign': 'campaigns',
               'intrusion-set': 'groups', 'malware': 'software', 'tool': 'software'}[kind]
    return f'https://attack.mitre.org/{section}/{attack_id.replace(".", "/")}/'


def build_attack_mapping_catalog(bundle: dict, *, attack_version: str, source_url: str) -> dict:
    if not isinstance(bundle, dict) or not isinstance(bundle.get('objects'), list):
        raise ValueError('STIX bundle must contain an objects list')
    if not isinstance(attack_version, str) or not attack_version.strip():
        raise ValueError('An ATT&CK release version is required')
    # Resolve revisions before filtering, so older active revisions cannot resurrect revoked objects.
    revisions = {}
    for obj in bundle['objects']:
        if not isinstance(obj, dict) or not isinstance(obj.get('id'), str):
            continue
        previous = revisions.get(obj['id'])
        modified = obj.get('modified') if isinstance(obj.get('modified'), str) else ''
        previous_modified = previous.get('modified', '') if previous else ''
        if previous is None or modified >= (previous_modified if isinstance(previous_modified, str) else ''):
            revisions[obj['id']] = obj
    active = [obj for obj in revisions.values() if not obj.get('revoked') and not obj.get('x_mitre_deprecated')]
    entities, stix_ids = {}, {}
    for obj in active:
        kind = obj.get('type')
        if not isinstance(kind, str) or kind not in _ID_PATTERNS:
            continue
        identifier = _attack_id(obj)
        name = obj.get('name')
        if kind not in _ID_PATTERNS or identifier is None or not isinstance(name, str) or not name.strip():
            continue
        if identifier in entities:
            raise ValueError(f'Duplicate ATT&CK ID: {identifier}')
        phases = obj.get('kill_chain_phases', [])
        tactics = sorted({phase['phase_name'] for phase in phases
                          if isinstance(phase, dict) and phase.get('kill_chain_name') == 'mitre-attack'
                          and isinstance(phase.get('phase_name'), str)}) if isinstance(phases, list) else []
        entities[identifier] = {'id': identifier, 'stix_id': obj['id'], 'type': kind, 'name': name.strip(),
                                'aliases': sorted(set(_strings(obj.get('aliases')) + _strings(obj.get('x_mitre_aliases')))),
                                'url': attack_url(kind, identifier), 'tactics': tactics,
                                'is_subtechnique': obj.get('x_mitre_is_subtechnique') is True}
        stix_ids[obj['id']] = identifier
    edges = []
    for obj in active:
        if obj.get('type') != 'relationship':
            continue
        if not isinstance(obj.get('source_ref'), str) or not isinstance(obj.get('target_ref'), str):
            continue
        source, target = stix_ids.get(obj.get('source_ref')), stix_ids.get(obj.get('target_ref'))
        kind = obj.get('relationship_type')
        if source is None or target is None or not isinstance(kind, str) or kind not in _PAIRS:
            continue
        if (entities[source]['type'], entities[target]['type']) not in _PAIRS[kind]:
            continue
        description = obj.get('description')
        edges.append({'id': obj['id'], 'type': kind, 'source_id': source, 'target_id': target,
                      'description': description if isinstance(description, str) else ''})
    return {'schema_version': 1,
            'metadata': {'source': 'MITRE ATT&CK', 'domain': 'enterprise-attack',
                         'attack_version': attack_version.strip(), 'source_url': source_url},
            'entities': [entities[key] for key in sorted(entities)],
            'relationships': sorted(edges, key=lambda item: item['id'])}


class AttackCatalog:
    def __init__(self, payload: dict):
        if not isinstance(payload, dict) or type(payload.get('schema_version')) is not int or payload['schema_version'] != 1:
            raise ValueError('Unsupported ATT&CK mapping catalog')
        metadata = payload.get('metadata')
        if not isinstance(metadata, dict) or not isinstance(metadata.get('attack_version'), str) or not metadata['attack_version'].strip():
            raise ValueError('Missing ATT&CK catalog version')
        if not isinstance(payload.get('entities'), list) or not isinstance(payload.get('relationships'), list):
            raise ValueError('Invalid ATT&CK graph')
        self.version = metadata['attack_version']
        self.entities, self.relationships = {}, {}
        self.outgoing, self.attributed = defaultdict(list), defaultdict(list)
        self.names = defaultdict(set)
        aliases = defaultdict(set)
        alias_owners = defaultdict(set)
        for node in payload['entities']:
            if not isinstance(node, dict) or not isinstance(node.get('type'), str) or node['type'] not in _ID_PATTERNS:
                raise ValueError('Invalid ATT&CK entity')
            kind, identifier = node['type'], node.get('id')
            if (not isinstance(identifier, str) or not re.fullmatch(_ID_PATTERNS[kind], identifier)
                    or not isinstance(node.get('name'), str) or not node['name'].strip() or identifier in self.entities):
                raise ValueError('Invalid or duplicate ATT&CK entity')
            # Construct links from validated IDs rather than trusting catalog URLs.
            self.entities[identifier] = {**node, 'url': attack_url(kind, identifier)}
            self.names[(kind, node['name'].casefold())].add(identifier)
            for alias in [node['name'], *_strings(node.get('aliases'))]:
                alias_owners[alias.casefold()].add(identifier)
            if kind == 'campaign':
                for alias in [node['name'], *_strings(node.get('aliases'))]:
                    if len(alias) >= 4 and alias.casefold() not in ('operation', 'campaign', 'malware', 'ransomware'):
                        aliases[alias.casefold()].add(identifier)
        for edge in payload['relationships']:
            if not isinstance(edge, dict) or not isinstance(edge.get('id'), str) or not edge['id'].startswith('relationship--'):
                raise ValueError('Invalid relationship ID')
            source, target, kind = edge.get('source_id'), edge.get('target_id'), edge.get('type')
            if (source not in self.entities or target not in self.entities or kind not in _PAIRS
                    or (self.entities[source]['type'], self.entities[target]['type']) not in _PAIRS[kind]
                    or edge['id'] in self.relationships or not isinstance(edge.get('description'), str)):
                raise ValueError('Invalid or duplicate ATT&CK relationship')
            self.relationships[edge['id']] = edge
            self.outgoing[source].append(edge)
            if kind == 'attributed-to':
                self.attributed[target].append(edge)
        self.campaign_aliases = [(re.compile(r'(?<![\w.-])' + r'[^\S\r\n]+'.join(re.escape(part) for part in alias.split()) + r'(?![\w-]|\.[\w.-])', re.IGNORECASE), next(iter(ids)))
                                 for alias, ids in sorted(aliases.items()) if len(ids) == 1 and len(alias_owners[alias]) == 1]

    @classmethod
    def load(cls, path: Path):
        try:
            return cls(json.loads(path.read_text(encoding='utf-8')))
        except (OSError, UnicodeError, ValueError, TypeError, KeyError):
            logger.warning('ATT&CK mapping catalog unavailable: %s', path)
            return None

    def detect(self, article: Article) -> AttackMapping:
        text = '\n'.join([article.title, article.summary, *article.tags])
        cleaned = mask_references(refang(text))
        identifiers = {match.group().upper() for match in _IDS.finditer(cleaned)} & self.entities.keys()
        # Trusted MITRE links are explicit references; other URL path tokens are ignored.
        sections = {'techniques': {'attack-pattern'}, 'campaigns': {'campaign'},
                    'groups': {'intrusion-set'}, 'software': {'malware', 'tool'}}
        for match in re.finditer(r'(?<![\w])https?://attack\.mitre\.org/(techniques|campaigns|groups|software)/([TGSC][0-9]{4})(?:/([0-9]{3}))?/?(?![\w./-])', refang(text), re.IGNORECASE):
            section = match[1].lower()
            if match[3] and section != 'techniques':
                continue
            identifier = match[2].upper() + ('.' + match[3] if match[3] else '')
            if identifier in self.entities and self.entities[identifier]['type'] in sections[section]:
                identifiers.add(identifier)
        identifiers.update(identifier for pattern, identifier in self.campaign_aliases if pattern.search(cleaned))
        for kind, names in (('intrusion-set', article.threat_actors), ('malware', article.malware)):
            for name in names:
                ids = self.names.get((kind, name.casefold()), set())
                if len(ids) == 1:
                    identifiers.update(ids)
        return AttackMapping(catalog_version=self.version, entity_ids=sorted(identifiers),
                             technique_ids=sorted(i for i in identifiers if self.entities[i]['type'] == 'attack-pattern'),
                             campaign_ids=sorted(i for i in identifiers if self.entities[i]['type'] == 'campaign'))

    def describe(self, mapping: AttackMapping | None) -> dict:
        result = {'catalog_version': mapping.catalog_version if mapping else self.version,
                  'status': 'ok', 'techniques': [], 'campaigns': [], 'relationships': []}
        if mapping is None:
            result['status'] = 'not_enriched'
            return result
        if mapping.catalog_version != self.version:
            result['status'] = 'version_mismatch'
            return result
        direct = set(mapping.entity_ids) & self.entities.keys()
        edges = {}
        def add(edge):
            edges[edge['id']] = edge
        for identifier in sorted(direct):
            for edge in self.outgoing[identifier]:
                add(edge)
                if edge['type'] == 'uses' and self.entities[edge['target_id']]['type'] in ('malware', 'tool'):
                    for software_edge in self.outgoing[edge['target_id']]:
                        if software_edge['type'] == 'uses':
                            add(software_edge)
            if self.entities[identifier]['type'] == 'intrusion-set':
                for edge in self.attributed[identifier]:
                    add(edge)
        related = direct | {edge[key] for edge in edges.values() for key in ('source_id', 'target_id')}
        for identifier in sorted(related):
            if self.entities[identifier]['type'] == 'attack-pattern':
                for edge in self.outgoing[identifier]:
                    if edge['type'] == 'subtechnique-of':
                        add(edge)
                        related.add(edge['target_id'])
        for identifier in sorted(related):
            node = self.entities[identifier]
            record = {**node, 'basis': 'article' if identifier in direct else 'catalog'}
            if node['type'] == 'attack-pattern': result['techniques'].append(record)
            if node['type'] == 'campaign': result['campaigns'].append(record)
        result['relationships'] = [{**edge, 'source': self.entities[edge['source_id']],
                                    'target': self.entities[edge['target_id']], 'basis': 'catalog'}
                                   for edge in sorted(edges.values(), key=lambda item: item['id'])]
        return result
