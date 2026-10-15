from pathlib import Path

import yaml


def test_production_compose_requires_application_database_credentials():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    database_url = compose["services"]["threatfade"]["environment"]["THREATFADE_DATABASE_URL"]

    assert "${THREATFADE_APP_DB_USER:?set THREATFADE_APP_DB_USER}" in database_url
    assert "${THREATFADE_APP_DB_PASSWORD:?set THREATFADE_APP_DB_PASSWORD}" in database_url


def test_production_compose_requires_postgres_superuser_password():
    compose = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    postgres_password = compose["services"]["postgres"]["environment"]["POSTGRES_PASSWORD"]

    assert postgres_password == "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}"
