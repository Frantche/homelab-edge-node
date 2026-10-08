SHELL := /usr/bin/env bash

.PHONY: quality test build ci-bootstrap

quality:
	python -m pytest -q
	go test ./...
	go vet ./...
	go build ./cmd/edge-manager ./cmd/edge-kubernetes-controller
	docker build --tag homelab-edge-node:ci .
	yamllint .
	ansible-lint
	shellcheck scripts/*.sh ci/*.sh ci/lib/*.sh ci/scenarios/*.sh
	ci/validate-collection.sh

test:
	python -m pytest -q
	go test ./...

build:
	ansible-galaxy collection build --force

ci-bootstrap:
	sudo ci/scenarios/bootstrap-user-journey.sh
