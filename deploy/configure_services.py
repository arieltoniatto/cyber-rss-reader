"""Render reviewable units; --install copies them to the user's systemd directory."""
import argparse
import math
import os
from pathlib import Path
import tempfile


def quote_unit(value: Path, *, command=False) -> str:
    text = str(value)
    if '\n' in text or '\r' in text:
        raise ValueError('Service paths cannot contain newlines')
    text = text.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%')
    if command:
        text = text.replace('$', '$$')
    return '"' + text + '"'


def write_new_or_identical(path: Path, content: str) -> None:
    if path.exists():
        if path.read_text() != content:
            raise FileExistsError(f'Refusing to overwrite different configuration: {path}')
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    try:
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def render(project: Path, output: Path, *, port=8000, interval=21600, keep=14) -> list[Path]:
    project = project.resolve()
    python = project / '.venv/bin/python'
    if not python.is_file():
        raise FileNotFoundError(python)
    if not 1 <= port <= 65535 or not math.isfinite(interval) or interval <= 0 or keep < 1:
        raise ValueError('Invalid port, collection interval or backup retention')
    environment = project / '.env.services'
    if not environment.exists():
        # Quotes follow EnvironmentFile syntax, with no shell evaluation.
        runtime = str(project).replace('\\', '\\\\').replace('"', '\\"')
        if '\n' in runtime or '\r' in runtime:
            raise ValueError('Runtime directory cannot contain newlines')
        write_new_or_identical(environment, f'CYBER_RSS_DATA_DIR="{runtime}"\nPYTHONUNBUFFERED=1\n')
    substitutions = {'PROJECT': str(project).replace('%', '%%'), 'ENVIRONMENT': str(environment).replace('%', '%%'),
                     'PYTHON': quote_unit(python, command=True), 'PORT': str(port),
                     'INTERVAL': str(interval), 'KEEP': str(keep)}
    paths=[]
    for template in sorted((Path(__file__).parent / 'systemd').glob('*.in')):
        content = template.read_text()
        for name, value in substitutions.items():
            content = content.replace('@' + name + '@', value)
        path = output / template.name.removesuffix('.in')
        write_new_or_identical(path, content)
        paths.append(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--interval', type=float, default=21600)
    parser.add_argument('--keep', type=int, default=14)
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    paths = render(args.project, args.output or args.project / 'deploy/generated',
                   port=args.port, interval=args.interval, keep=args.keep)
    for path in paths:
        print(f'Rendered: {path}')
    if args.install:
        directory = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'systemd/user'
        for path in paths:
            target = directory / path.name
            write_new_or_identical(target, path.read_text())
            print(f'Installed: {target}')
        print('Run systemctl --user daemon-reload and enable the API, worker and backup timer.')


if __name__ == '__main__':
    main()
