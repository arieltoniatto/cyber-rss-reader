"""Static checks for the GKE manifests in deploy/gke (no cluster required)."""
from pathlib import Path

import pytest
import yaml

from web_api.security import PUBLIC_PATHS

ROOT = Path(__file__).resolve().parents[3]
GKE = ROOT / 'deploy/gke'
MANIFESTS = sorted(path for path in GKE.rglob('*.yaml') if path.name != 'kustomization.yaml')


def documents():
    return [document for path in MANIFESTS for document in yaml.safe_load_all(path.read_text()) if document]


def pod_specs():
    for document in documents():
        kind = document['kind']
        if kind == 'Pod':
            yield document['metadata']['name'], document['spec']
        elif kind == 'Deployment':
            yield document['metadata']['name'], document['spec']['template']['spec']
        elif kind == 'CronJob':
            yield document['metadata']['name'], document['spec']['jobTemplate']['spec']['template']['spec']


def test_kustomization_lists_every_base_manifest():
    kustomization = yaml.safe_load((GKE / 'kustomization.yaml').read_text())
    base = sorted(path.name for path in GKE.glob('*.yaml') if path.name != 'kustomization.yaml')
    assert sorted(kustomization['resources']) == base
    assert all(image.get('newTag') != 'latest' for image in kustomization['images'])


@pytest.mark.parametrize('name, spec', list(pod_specs()), ids=[name for name, _ in pod_specs()])
def test_pods_are_hardened(name, spec):
    pod = spec['securityContext']
    assert pod['runAsNonRoot'] is True and pod['seccompProfile']['type'] == 'RuntimeDefault'
    assert spec['automountServiceAccountToken'] is False
    assert spec['serviceAccountName'] == 'cyber-rss'
    containers = spec.get('initContainers', []) + spec['containers']
    for container in containers:
        context = container['securityContext']
        assert context['readOnlyRootFilesystem'] is True
        assert context['allowPrivilegeEscalation'] is False
        assert context['capabilities']['drop'] == ['ALL']
        assert container['resources']['requests']['memory']
        assert container['resources']['limits']['memory']
        # The app image is the kustomize placeholder, pinned by `images` in kustomization.yaml.
        image = container['image']
        assert image == 'cyber-rss-reader' or (':' in image and not image.endswith(':latest'))
    mounts = {mount['mountPath'] for container in spec['containers'] for mount in container.get('volumeMounts', [])}
    assert {'/runtime', '/tmp'} <= mounts


def test_api_probes_use_public_health_and_liveness_does_not_depend_on_database():
    api = next(spec for name, spec in pod_specs() if name == 'cyber-rss-api')['containers'][0]
    assert api['readinessProbe']['httpGet']['path'] in PUBLIC_PATHS
    assert 'httpGet' not in api['livenessProbe']
    backend = next(d for d in documents() if d['kind'] == 'BackendConfig')
    assert backend['spec']['healthCheck']['requestPath'] in PUBLIC_PATHS
    assert backend['spec']['iap']['enabled'] is True


def test_collector_runs_once_per_job_without_overlap():
    cronjob = next(d for d in documents() if d['kind'] == 'CronJob')
    assert cronjob['spec']['concurrencyPolicy'] == 'Forbid'
    command = cronjob['spec']['jobTemplate']['spec']['template']['spec']['containers'][0]['command']
    assert command[:3] == ['python', '-m', 'app.worker'] and '--once' in command


def test_configmap_only_sets_known_settings_without_credentials():
    config = next(d for d in documents() if d['kind'] == 'ConfigMap')['data']
    source = '\n'.join(path.read_text() for path in (ROOT / 'src').rglob('*.py'))
    for key in config:
        assert f"'{key}'" in source or f'"{key}"' in source, key
    assert ':' not in config['CYBER_RSS_DATABASE_URL'].split('@')[0].removeprefix('postgresql://')


def test_egress_blocks_private_and_metadata_ranges_for_general_traffic():
    egress = next(d for d in documents() if d['kind'] == 'NetworkPolicy' and d['metadata']['name'] == 'egress')
    internet = [rule for rule in egress['spec']['egress']
                if rule['to'][0].get('ipBlock', {}).get('cidr') == '0.0.0.0/0']
    assert len(internet) == 1
    assert {'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16'} <= set(
        internet[0]['to'][0]['ipBlock']['except'])
