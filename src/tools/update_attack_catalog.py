"""Build a versioned ATT&CK graph from a local STIX release."""
import argparse
from config.paths import ATTACK_MAPPING_CATALOG_FILE, MITRE_ATTACK_DIRECTORY
from cti.attack_mapping import build_attack_mapping_catalog
from tools.update_malware_catalog import _latest_stix_file, _version_from_filename, _read_json
from tools.update_threat_actor_catalog import _write_json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path)
    parser.add_argument('--output', type=Path, default=ATTACK_MAPPING_CATALOG_FILE)
    parser.add_argument('--version', help='Release version for bundles without a versioned filename.')
    args = parser.parse_args()
    source = args.input or _latest_stix_file(MITRE_ATTACK_DIRECTORY)
    if source.resolve() == args.output.resolve():
        parser.error('--input and --output must differ')
    version = args.version or _version_from_filename(source)
    if not version:
        parser.error('Supply --version for an unversioned bundle filename')
    catalog = build_attack_mapping_catalog(_read_json(source), attack_version=version, source_url=source.name)
    _write_json(args.output, catalog)
    print(f"Generated ATT&CK {version}: {len(catalog['entities'])} entities, {len(catalog['relationships'])} relationships.")


if __name__ == '__main__':
    main()
