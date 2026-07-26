# Disabled inherited workflows

The following inherited workflows are intentionally absent from the active
workflow directory on `NewArc`:

- `build_and_run_chain_simulator_and_execute_system_test.yml` uploaded reports
  to external Cloudflare R2 storage, force-pushed `gh-pages`, and notified Slack.
- `create_release.yml` created and uploaded GitHub releases.
- `docker-keygenerator.yaml` authenticated to Docker Hub and published
  `multiversx/chain-keygenerator`.

They must not be re-enabled without a reviewed Xorewa-owned destination,
least-privilege credentials, and an explicit release/deployment approval.
Active workflows are restricted to `NewArc` and perform validation only.
