"""Inspect alert delivery state or explicitly dispatch queued alerts."""
import argparse
import json
import time
from pathlib import Path

from alerts.config import AlertSettings
from alerts.service import AlertService
from config.paths import ARTICLE_DATABASE_FILE
from storage.factory import create_repository


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', type=Path, default=ARTICLE_DATABASE_FILE)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--status', action='store_true', help='Inspect counts without sending (default).')
    actions.add_argument('--dispatch', action='store_true', help='Send a bounded batch of due alerts.')
    actions.add_argument('--watch', action='store_true', help='Dispatch due alerts periodically.')
    actions.add_argument('--retry-failed', action='store_true', help='Requeue failed alerts without sending.')
    parser.add_argument('--interval', type=int, default=60)
    args = parser.parse_args()
    if args.interval < 1:
        parser.error('--interval must be positive')
    try:
        settings = AlertSettings.from_environment()
        service = AlertService(create_repository(database_file=args.database), settings)
        if args.retry_failed:
            print(json.dumps({'requeued': service.outbox.retry_failed()}))
        elif args.dispatch or args.watch:
            while True:
                print(json.dumps(service.dispatch()), flush=True)
                if not args.watch:
                    break
                time.sleep(args.interval)
        else:
            print(json.dumps(service.outbox.status(), indent=2))
    except ValueError as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
