# Example scans

This folder holds **real** scans of public images, used to demo `vulnrank` on realistic data.
They are not used by the test suite (tests use small hand-written files in `tests/fixtures/`).

## Generating the scans

Install [Trivy](https://trivy.dev/), then run from the repository root:

```sh
# Trivy JSON reports
trivy image --format json --output examples/python-3.8.trivy.json python:3.8
trivy image --format json --output examples/nginx-1.19.trivy.json nginx:1.19
trivy image --format json --output examples/juice-shop.trivy.json bkimminich/juice-shop

# CycloneDX SBOMs with vulnerabilities
trivy image --scanners vuln --format cyclonedx --output examples/python-3.8.cdx.json python:3.8
trivy image --scanners vuln --format cyclonedx --output examples/nginx-1.19.cdx.json nginx:1.19
trivy image --scanners vuln --format cyclonedx --output examples/juice-shop.cdx.json bkimminich/juice-shop
```

With [Grype](https://github.com/anchore/grype):

```sh
grype nginx:1.19 -o json --file examples/nginx-1.19.grype.json
grype bkimminich/juice-shop -o json --file examples/juice-shop.grype.json
```

`--scanners vuln` matters for CycloneDX: by default `--format cyclonedx` produces an SBOM
**without** vulnerabilities.

The `nginx:1.19` and Juice Shop scans are committed. The `python:3.8` scans are about 50 MB
each, too large for the repository, so generate them locally when you need them.

Scan results change over time as new CVEs are published, so the output of `vulnrank` on
these files will drift too. Re-run the commands above to refresh them.
