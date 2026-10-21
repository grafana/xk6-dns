WORKFLOW        ?= .github/workflows/all.yml
K6_CI_REF       := $(shell grep -oE 'grafana/k6-ci/[^@[:space:]]+@[A-Za-z0-9._/-]+' $(WORKFLOW) | head -n1 | cut -d@ -f2)
LINT_CONFIG_URL := https://raw.githubusercontent.com/grafana/k6-ci/$(K6_CI_REF)/.golangci.yml
LINT_CONFIG     ?= .golangci.yml

$(LINT_CONFIG): $(WORKFLOW)
	curl -fsSL $(LINT_CONFIG_URL) -o $@

.PHONY: lint
lint: $(LINT_CONFIG)
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$$(head -n1 $(LINT_CONFIG) | tr -d '# ') \
	  run --config=$(LINT_CONFIG) ./...

.PHONY: clean-lint
clean-lint:
	rm -f $(LINT_CONFIG)
