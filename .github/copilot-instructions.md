# GitHub Copilot Instructions

## Running Tests Locally Before Pushing

This repository uses Poetry for dependency management and includes several automated checks that run in CI. To ensure your changes pass all CI checks, please run the following commands locally before pushing:

### Prerequisites

Install Poetry if you haven't already:
```bash
pipx install poetry
```

Install project dependencies:
```bash
poetry install --with dev
```

### Code Formatting

Run Black to format your code:
```bash
poetry run black .
```

### Import Sorting

Run isort to sort imports:
```bash
poetry run isort .
```

### Linting

Run flake8 to check for code style issues:
```bash
flake8 .
```

Note: The maximum line length is configured to 120 characters in `.flake8`.

### Testing

Run pytest with coverage:
```bash
poetry run pytest tests/ -v --cov=keystone_keycloak_backend --cov-report=term-missing
```

### Build Package

Verify the package builds successfully:
```bash
poetry build
```

### Run All Checks

To run all checks at once, you can use this command sequence:
```bash
poetry run black . && poetry run isort . && flake8 . && poetry run pytest tests/ -v --cov=keystone_keycloak_backend --cov-report=term-missing && poetry build
```

## Python Version Support

This project supports Python 3.8, 3.9, 3.10, 3.11, and 3.12. Make sure your changes are compatible with these versions.

## Testing with Docker Compose

For integration testing with Keycloak and Keystone:
```bash
docker compose up -d
source hack/testrc
openstack user list
```
