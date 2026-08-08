SHELL := /usr/bin/env bash

.PHONY: quality test build ci-bootstrap

quality:
	python -m pytest -q
	yamllint .
	ansible-lint
	shellcheck scripts/*.sh ci/*.sh ci/lib/*.sh ci/scenarios/*.sh
	ci/validate-collection.sh

test:
	python -m pytest -q

build:
	ansible-galaxy collection build --force

ci-bootstrap:
	sudo ci/scenarios/bootstrap-user-journey.sh
