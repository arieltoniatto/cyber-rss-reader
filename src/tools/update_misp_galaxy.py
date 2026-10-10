"""Refresh the local MISP Threat Actor Galaxy used by all collection modes."""
import argparse
import json
import os
from pathlib import Path

from config.paths import MISP_GALAXY_DIRECTORY, MISP_GALAXY_SEED_FILE, MISP_GALAXY_SEED_METADATA
from cti.misp_galaxy_store import MispGalaxyStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=MISP_GALAXY_DIRECTORY)
    parser.add_argument('--interval-hours', type=float,
                        default=float(os.environ.get('CYBER_RSS_MISP_UPDATE_INTERVAL_HOURS', '168')),
                        help='Hours between successful checks (default: 168 / seven days).')
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--force', action='store_true', help='Download now, ignoring the interval and failure backoff.')
    actions.add_argument('--status', action='store_true', help='Show local status without network requests.')
    args = parser.parse_args()
    try:
        store = MispGalaxyStore(args.directory, MISP_GALAXY_SEED_FILE, MISP_GALAXY_SEED_METADATA,
                               interval_hours=args.interval_hours)
    except ValueError as exc:
        parser.error(str(exc))
    outcome = 'status' if args.status else store.refresh(force=args.force)
    print(json.dumps({'result': outcome, **store.status()}, indent=2, ensure_ascii=False))
    if outcome == 'failed':
        parser.exit(1, 'Update failed; the prior local snapshot was preserved.\n')


if __name__ == '__main__':
    main()
