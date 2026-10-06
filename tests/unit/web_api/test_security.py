import base64
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from web_api.app import create_app
from web_api.security import create_credentials, RequestBudget, SecuritySettings


@pytest.fixture
def credentials():
    return create_credentials('reader', 'A strong test password é 123')


@pytest.mark.parametrize('path', ['/', '/assets/app.js', '/articles', '/search?q=test',
                                  '/feeds', '/health', '/docs', '/openapi.json'])
def test_every_http_route_requires_authentication_over_https(tmp_path, credentials, path):
    settings = SecuritySettings(credentials=credentials)
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3', security=settings),
                    base_url='https://testserver') as client:
        response = client.get(path)
        assert response.status_code == 401
        assert response.headers['www-authenticate'].startswith('Basic ')
        assert response.headers['cache-control'] == 'no-store'
        assert 'max-age=' in response.headers['strict-transport-security']
        assert client.get(path, auth=('reader', 'incorrect')).status_code == 401
        assert client.get(path, auth=('reader', 'A strong test password é 123')).status_code == 200


def test_http_never_challenges_or_accepts_credentials_and_ignores_spoofed_proxy(tmp_path, credentials):
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3',
                              security=SecuritySettings(credentials=credentials))) as client:
        response = client.get('/health', auth=('reader', 'A strong test password é 123'),
                              headers={'X-Forwarded-Proto': 'https'})
        assert response.status_code == 426
        assert 'www-authenticate' not in response.headers


@pytest.mark.parametrize('header', ['Basic ???', 'Bearer value', 'Basic '+base64.b64encode(b'no-colon').decode(),
                                  'Basic '+base64.b64encode(b'\xff:bad').decode(), 'Basic '+'a'*3000])
def test_malformed_authentication_returns_401(tmp_path, credentials, header):
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3',
                              security=SecuritySettings(credentials=credentials)),
                    base_url='https://testserver') as client:
        assert client.get('/health', headers={'Authorization': header}).status_code == 401


def test_failed_login_rate_budget_cannot_be_bypassed_with_forwarded_ip(tmp_path, credentials):
    settings = SecuritySettings(credentials=credentials, burst=2, per_minute=1)
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3', security=settings),
                    base_url='https://testserver') as client:
        for ip in ('1.2.3.4', '5.6.7.8'):
            assert client.get('/health', headers={'X-Forwarded-For': ip}).status_code == 401
        response = client.get('/health', auth=('reader', 'A strong test password é 123'))
        assert response.status_code == 429
        assert int(response.headers['retry-after']) >= 1


def test_budget_refills_separates_clients_enforces_global_cap_and_bounds_memory():
    now = [0.0]
    budget = RequestBudget(SecuritySettings(burst=2, per_minute=2, global_burst=3,
                                          global_per_minute=3, max_clients=2), clock=lambda: now[0])
    assert budget.allow('a') == 0
    assert budget.allow('a') == 0
    assert budget.allow('a') == 30
    assert budget.allow('b') == 0
    assert budget.allow('b') == 20  # global budget exhausted
    assert budget.allow('c') > 0   # active clients are not evicted
    assert len(budget.clients) == 2
    now[0] = 60
    assert budget.allow('c') == 0
    assert len(budget.clients) == 1


def test_environment_fails_closed_on_missing_malformed_or_world_readable_auth(tmp_path, monkeypatch, credentials):
    file = tmp_path / 'credentials.json'
    monkeypatch.setenv('CYBER_RSS_AUTH_FILE', str(file))
    with pytest.raises(FileNotFoundError):
        SecuritySettings.from_environment()
    file.write_text(json.dumps(credentials))
    file.chmod(0o644)
    with pytest.raises(ValueError, match='0600'):
        SecuritySettings.from_environment()
    file.chmod(0o600)
    assert SecuritySettings.from_environment().credentials == credentials
    file.write_text('{')
    with pytest.raises(ValueError):
        SecuritySettings.from_environment()


@pytest.mark.parametrize('args', [['--host', '0.0.0.0'], ['--host', '192.168.1.10'],
                                 ['--host', '::'], ['--ssl-certfile', 'only-cert.pem']])
def test_cli_refuses_unprotected_external_listener_or_incomplete_tls(args, monkeypatch):
    monkeypatch.delenv('CYBER_RSS_AUTH_FILE', raising=False)
    monkeypatch.delenv('CYBER_RSS_TLS_CERT_FILE', raising=False)
    monkeypatch.delenv('CYBER_RSS_TLS_KEY_FILE', raising=False)
    result = subprocess.run([sys.executable, '-m', 'web_api.app', *args], capture_output=True, text=True)
    assert result.returncode == 2
    assert 'required' in result.stderr or 'require' in result.stderr


def test_lan_certificate_setup_creates_valid_identity_keeps_ca_and_credentials_on_renewal(tmp_path):
    spec = importlib.util.spec_from_file_location('configure_https', Path(__file__).resolve().parents[3] / 'deploy/configure_https.py')
    deployment = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deployment)
    project = tmp_path / 'project with spaces'
    (project / '.venv/bin').mkdir(parents=True)
    (project / '.venv/bin/python').touch()
    output = project / 'deploy/generated/https'
    names = ['localhost', '127.0.0.1', '192.168.1.11']
    dropin = deployment.prepare(project, output, names=names)
    originals = {name: (output / name).read_bytes() for name in ('ca.key', 'ca.crt', 'credentials.json', 'access.txt')}
    assert ' -m web_api.app --host 0.0.0.0 --port 8443' in dropin.read_text()
    for name in ('credentials.json', 'ca.key', 'server.key', 'access.txt', '.env.https'):
        assert (output / name).stat().st_mode & 0o077 == 0
    verify = subprocess.run(['openssl', 'verify', '-CAfile', str(output / 'ca.crt'),
                             '-verify_ip', '192.168.1.11', str(output / 'server.crt')], capture_output=True)
    assert verify.returncode == 0
    old_server = (output / 'server.crt').read_bytes()
    deployment.prepare(project, output, names=names, renew=True)
    assert (output / 'server.crt').read_bytes() != old_server
    assert all((output / name).read_bytes() == value for name, value in originals.items())
    with pytest.raises(ValueError):
        deployment.san_names(['192.168.1.11\nInjected'])
    with pytest.raises(ValueError):
        deployment.san_names(['8.8.8.8'])
    with pytest.raises(ValueError):
        deployment.san_names(['0.0.0.0'])
