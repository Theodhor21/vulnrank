# vulnrank

Turn a raw vulnerability scan into a short, prioritised list, with a reason for every decision.

A scanner like Trivy can return thousands of findings for a single image. `vulnrank` enriches
each finding with exploit likelihood (FIRST EPSS), known exploitation (CISA KEV) and your own
asset context, then ranks them into priority tiers P1–P4 using transparent, deterministic rules.

> **Status:** work in progress. See the roadmap below.

## Roadmap

- [x] Project scaffold (uv, ruff, pyright strict, pytest, CI)
- [x] Domain models and rule-based scoring
- [x] Input adapters: Trivy JSON, CycloneDX
- [x] Enrichment: EPSS and CISA KEV, with caching and offline mode
- [ ] CLI with table, JSON and Markdown output and a CI gate
- [ ] Portfolio polish: architecture diagram, ADRs, badges

## Development

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync          # create .venv and install dependencies
make check       # lint + type check + tests
```

Individual targets: `make lint`, `make format`, `make typecheck`, `make test`.

## License

[MIT](LICENSE)
