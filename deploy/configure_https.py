"""Prepare a private LAN HTTPS identity and a reviewable API systemd override."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile

from web_api.security import create_credentials, SecuritySettings


def private_write(path: Path, content: str, *, overwrite=False):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, delete=False) as stream:
        pending = Path(stream.name)
        stream.write(content)
    try:
        if overwrite:
            pending.replace(path)
        else:
            os.link(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def quoted(value: Path, *, unit=False):
    value = str(value)
    if '\n' in value or '\r' in value:
        raise ValueError('Paths cannot contain newlines')
    value = value.replace('\\', '\\\\').replace('"', '\\"')
    if unit:
        value = value.replace('%', '%%').replace('$', '$$')
    return '"' + value + '"'


def san_names(names: list[str]) -> list[str]:
    result = []
    for name in names:
        try:
            address = ipaddress.ip_address(name)
            if not address.is_private or address.is_unspecified or address.is_multicast:
                raise ValueError('Use private or loopback IP addresses for LAN HTTPS')
            result.append('IP:' + str(address))
        except ValueError:
            if not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', name) or name.replace('.', '').isdigit():
                raise ValueError(f'Invalid LAN hostname/IP: {name}') from None
            result.append('DNS:' + name.lower())
    if not result:
        raise ValueError('At least one hostname/IP is required')
    return sorted(set(result))


def prepare(project: Path, output: Path, *, names: list[str], listen='0.0.0.0', port=8443,
            username='reader', renew=False):
    project, output = project.resolve(), output.resolve()
    # Listen addresses are literals, avoiding shell/systemd expansion and DNS changes.
    address = ipaddress.ip_address(listen)
    if (not address.is_private and not address.is_unspecified) or address.is_multicast:
        raise ValueError('Bind to a private, loopback or unspecified address')
    if not 1 <= port <= 65535:
        raise ValueError('Invalid HTTPS port')
    identities = san_names(names)
    python = project / '.venv/bin/python'
    if not python.is_file():
        raise FileNotFoundError(python)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    auth = output / 'credentials.json'
    ca_key, ca_cert = output / 'ca.key', output / 'ca.crt'
    server_key, server_cert = output / 'server.key', output / 'server.crt'
    metadata = output / 'identity.json'
    if metadata.exists() and json.loads(metadata.read_text())['names'] != identities and not renew:
        raise ValueError('Certificate identities changed; use --renew with the existing CA')
    if ca_key.exists() != ca_cert.exists():
        raise ValueError('Incomplete local CA; restore the missing file before proceeding')
    if auth.exists():
        if auth.stat().st_mode & 0o077:
            raise ValueError('Existing credential file must have permissions 0600')
        SecuritySettings(credentials=json.loads(auth.read_text()))
    else:
        password = secrets.token_urlsafe(32)
        private_write(auth, json.dumps(create_credentials(username, password), indent=2) + '\n')
        private_write(output / 'access.txt', f'Username: {username}\nPassword: {password}\n')
    with tempfile.TemporaryDirectory(dir=output) as staging:
        directory = Path(staging)
        def openssl(*args):
            subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)
        if not ca_cert.exists():
            openssl('req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650',
                    '-subj', '/CN=Cyber RSS LAN CA', '-keyout', directory / 'ca.key', '-out', directory / 'ca.crt',
                    '-addext', 'basicConstraints=critical,CA:TRUE,pathlen:0',
                    '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
            private_write(ca_key, (directory / 'ca.key').read_text())
            private_write(ca_cert, (directory / 'ca.crt').read_text())
        if renew or not server_cert.exists() or not server_key.exists():
            openssl('req', '-new', '-newkey', 'rsa:3072', '-sha256', '-nodes',
                    '-subj', '/CN=Cyber RSS LAN', '-keyout', directory / 'server.key', '-out', directory / 'server.csr')
            extensions = directory / 'extensions.cnf'
            extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
                                  'extendedKeyUsage=serverAuth\nsubjectAltName=' + ','.join(identities) + '\n')
            openssl('x509', '-req', '-sha256', '-days', '365', '-in', directory / 'server.csr',
                    '-CA', ca_cert, '-CAkey', ca_key, '-set_serial', str(secrets.randbits(128)),
                    '-extfile', extensions, '-out', directory / 'server.crt')
            private_write(server_key, (directory / 'server.key').read_text(), overwrite=True)
            private_write(server_cert, (directory / 'server.crt').read_text(), overwrite=True)
            private_write(metadata, json.dumps({'names': identities}, indent=2) + '\n', overwrite=True)
    for file in (ca_key, server_key, auth, ca_cert, server_cert):
        file.chmod(0o600)
    subprocess.run(['openssl', 'verify', '-CAfile', str(ca_cert), str(server_cert)], check=True, capture_output=True)
    environment = output / '.env.https'
    private_write(environment, f'CYBER_RSS_AUTH_FILE={quoted(auth)}\n'
                  f'CYBER_RSS_TLS_CERT_FILE={quoted(server_cert)}\nCYBER_RSS_TLS_KEY_FILE={quoted(server_key)}\n'
                  'CYBER_RSS_RATE_PER_MINUTE=120\nCYBER_RSS_RATE_BURST=30\n'
                  'CYBER_RSS_RATE_GLOBAL_PER_MINUTE=600\nCYBER_RSS_RATE_GLOBAL_BURST=60\n', overwrite=True)
    dropin = output / 'https.conf'
    content = ('[Service]\nEnvironmentFile=' + str(environment).replace('%', '%%') + '\n'
               'ExecStart=\nExecStart=' + quoted(python, unit=True) +
               f' -m web_api.app --host {listen} --port {port}\n')
    if dropin.exists() and dropin.read_text() != content:
        raise FileExistsError(f'Refusing to overwrite a different service override: {dropin}')
    if not dropin.exists():
        private_write(dropin, content)
    return dropin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path)
    parser.add_argument('--names', nargs='+', required=True, help='Certificate LAN hostnames and private IPs')
    parser.add_argument('--listen', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=8443)
    parser.add_argument('--username', default='reader')
    parser.add_argument('--renew', action='store_true', help='Reissue the server certificate using the existing local CA')
    parser.add_argument('--install', action='store_true')
    args = parser.parse_args()
    output = args.output or args.project / 'deploy/generated/https'
    dropin = prepare(args.project, output, names=args.names, listen=args.listen,
                     port=args.port, username=args.username, renew=args.renew)
    print(f'Prepared: {dropin}')
    print(f'Private credentials: {dropin.parent / "access.txt"}')
    print(f'Client trust certificate (public): {dropin.parent / "ca.crt"}')
    if args.install:
        directory = Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config'))) / 'systemd/user/cyber-rss-api.service.d'
        target = directory / 'https.conf'
        if target.exists() and target.read_text() != dropin.read_text():
            raise FileExistsError(f'Refusing to overwrite a different installed override: {target}')
        if not target.exists():
            private_write(target, dropin.read_text())
        print(f'Installed: {target}')
        print('Reload systemd and restart ONLY cyber-rss-api.service to activate HTTPS.')


if __name__ == '__main__':
    main()
