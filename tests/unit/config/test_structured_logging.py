import io
import json
import logging

from fastapi.testclient import TestClient
import pytest

from config.structured_logging import (CloudJSONFormatter, configure_json_logging,
                                       configure_logging_from_environment, log_format_from_environment)


@pytest.fixture(autouse=True)
def restore_logging():
    names = ('', 'uvicorn', 'uvicorn.error', 'uvicorn.access')
    saved = {name: (list(logging.getLogger(name).handlers), logging.getLogger(name).level,
                    logging.getLogger(name).propagate) for name in names}
    yield
    for name, (handlers, level, propagate) in saved.items():
        logger = logging.getLogger(name)
        logger.handlers[:] = handlers
        logger.setLevel(level)
        logger.propagate = propagate


def lines(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_format_defaults_to_text_and_rejects_unknown_values(monkeypatch):
    monkeypatch.delenv('CYBER_RSS_LOG_FORMAT', raising=False)
    assert log_format_from_environment() == 'text'
    monkeypatch.setenv('CYBER_RSS_LOG_FORMAT', ' JSON ')
    assert log_format_from_environment() == 'json'
    monkeypatch.setenv('CYBER_RSS_LOG_FORMAT', 'xml')
    with pytest.raises(ValueError, match='CYBER_RSS_LOG_FORMAT'):
        log_format_from_environment()


def test_records_become_one_json_object_per_line_with_cloud_logging_fields():
    stream = io.StringIO()
    configure_json_logging(logging.INFO, stream)
    logger = logging.getLogger('cyber_rss.feeds')
    logger.debug('hidden below the level')
    logger.warning('Feed %s failed', 'Exemplo "ç"\nnext line')
    try:
        raise RuntimeError('boom')
    except RuntimeError:
        logging.getLogger('app.worker').exception('Collection failed')
    warning, error = lines(stream)
    assert warning['severity'] == 'WARNING'
    assert warning['message'] == 'Feed Exemplo "ç"\nnext line failed'
    assert warning['logger'] == 'cyber_rss.feeds'
    assert warning['time'].endswith('Z')
    assert warning['logging.googleapis.com/sourceLocation']['function'] == (
        'test_records_become_one_json_object_per_line_with_cloud_logging_fields')
    assert error['severity'] == 'ERROR'
    assert error['message'].startswith('Collection failed\nTraceback')
    assert 'RuntimeError: boom' in error['message']


def test_custom_levels_map_to_default_severity():
    record = logging.LogRecord('x', 25, __file__, 1, 'custom', None, None)
    assert json.loads(CloudJSONFormatter().format(record))['severity'] == 'DEFAULT'


def test_uvicorn_loggers_are_routed_through_json_with_http_request():
    for name in ('uvicorn', 'uvicorn.access'):
        logging.getLogger(name).addHandler(logging.StreamHandler(io.StringIO()))
        logging.getLogger(name).propagate = False
    stream = io.StringIO()
    configure_json_logging(logging.INFO, stream)
    logging.getLogger('uvicorn.access').info('%s - "%s %s HTTP/%s" %d', '10.0.0.1:5000', 'GET', '/health', '1.1', 200)
    logging.getLogger('uvicorn.error').info('Application startup complete.')
    access, startup = lines(stream)
    assert access['httpRequest'] == {'requestMethod': 'GET', 'requestUrl': '/health', 'protocol': 'HTTP/1.1',
                                     'status': 200}
    assert '10.0.0.1' not in json.dumps(access['httpRequest'])
    assert startup['message'] == 'Application startup complete.' and 'httpRequest' not in startup


def test_environment_setup_is_idempotent_and_keeps_first_level(monkeypatch):
    monkeypatch.setenv('CYBER_RSS_LOG_FORMAT', 'json')
    assert configure_logging_from_environment(logging.INFO) is True
    handlers = list(logging.getLogger().handlers)
    assert configure_logging_from_environment(logging.WARNING) is True
    assert logging.getLogger().handlers == handlers
    assert logging.getLogger().level == logging.INFO
    monkeypatch.setenv('CYBER_RSS_LOG_FORMAT', 'text')
    assert configure_logging_from_environment(logging.INFO) is False


def test_api_factory_enables_json_logging_only_when_requested(tmp_path, monkeypatch):
    from config.structured_logging import json_logging_active
    from web_api.app import create_app

    monkeypatch.delenv('CYBER_RSS_LOG_FORMAT', raising=False)
    create_app(database_file=tmp_path / 'archive.sqlite3')
    assert not json_logging_active()
    monkeypatch.setenv('CYBER_RSS_LOG_FORMAT', 'json')
    with TestClient(create_app(database_file=tmp_path / 'archive.sqlite3')) as client:
        assert client.get('/health').status_code == 200
    assert json_logging_active()
