import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('configure_services', Path(__file__).resolve().parents[3] / 'deploy/configure_services.py')
deployment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deployment)


def project(tmp_path):
    directory = tmp_path / 'project with spaces'
    (directory / '.venv/bin').mkdir(parents=True)
    (directory / '.venv/bin/python').touch()
    return directory


def test_render_uses_absolute_paths_and_preserves_existing_environment(tmp_path):
    directory = project(tmp_path)
    environment = directory / '.env.services'
    environment.write_text('CYBER_RSS_DATA_DIR=/custom/persistent/storage\n')
    units = deployment.render(directory, tmp_path / 'units')
    assert len(units) == 4
    assert environment.read_text() == 'CYBER_RSS_DATA_DIR=/custom/persistent/storage\n'
    api = next(path for path in units if path.name == 'cyber-rss-api.service').read_text()
    assert str(directory / '.venv/bin/python') in api
    assert 'Restart=always' in api
    assert '--host 127.0.0.1' in api
    assert deployment.render(directory, tmp_path / 'units') == units


def test_render_does_not_overwrite_different_units(tmp_path):
    directory = project(tmp_path)
    target = tmp_path / 'units/cyber-rss-api.service'
    target.parent.mkdir()
    target.write_text('Existing custom service')
    with pytest.raises(FileExistsError):
        deployment.render(directory, target.parent)
    assert target.read_text() == 'Existing custom service'


def test_command_paths_escape_specifiers_and_environment_expansion(tmp_path):
    assert deployment.quote_unit(Path('/project 10%/$APP/python'), command=True) == '"/project 10%%/$$APP/python"'
    with pytest.raises(ValueError):
        deployment.quote_unit(Path('/project\nInjected=command'))
