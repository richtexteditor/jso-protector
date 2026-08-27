# jso-protector Helm chart

Deploy `jso-protector` as a one-shot Kubernetes Job — or, when `cron.schedule` is set, a recurring CronJob. Pairs with the [Tekton template](../../ci/tekton.yaml) for shops that already run Tekton; this chart is for everything else.

## Quick install

```bash
helm install nightly-protect ./helm \
    --set repo.url=https://github.com/your-org/your-repo.git \
    --set repo.ref=$(git rev-parse HEAD) \
    --set credentials.apiKey=$JSO_API_KEY \
    --set credentials.apiPassword=$JSO_API_PASSWORD
```

Or, recommended for production, point at an existing Secret you manage out-of-band:

```bash
kubectl create secret generic jso-credentials \
    --from-literal=JSO_API_KEY=$JSO_API_KEY \
    --from-literal=JSO_API_PASSWORD=$JSO_API_PASSWORD

helm install nightly-protect ./helm \
    --set repo.url=https://github.com/your-org/your-repo.git \
    --set repo.ref=$(git rev-parse HEAD) \
    --set credentials.existingSecret=jso-credentials
```

## Recurring nightly protection

Set `cron.schedule` to a standard cron expression to deploy a `CronJob` instead of a one-shot `Job`:

```bash
helm install nightly-protect ./helm \
    --set repo.url=... \
    --set credentials.existingSecret=jso-credentials \
    --set cron.schedule="0 2 * * *"
```

Concurrency policy is `Forbid` — if last night's run is still going, tonight's run is skipped rather than queued.

## Values

| Key | Default | Notes |
|---|---|---|
| `repo.url` | placeholder | Git repo to clone in the init container. |
| `repo.ref` | `main` | Branch, tag, or SHA. |
| `credentials.existingSecret` | `""` | Use an out-of-band Secret if set; otherwise the chart creates one. |
| `credentials.apiKey` / `credentials.apiPassword` | `""` | Used only when `existingSecret` is empty. |
| `protect.configPath` | `jso.config.json` | jso-protector config in the repo. |
| `protect.preset` | `balanced` | `standard` / `balanced` / `maximum`. |
| `protect.manifestPath` / `protect.reportPath` | `dist-protected/...` | Where the manifest and report land in the workspace. |
| `images.git` / `images.node` | `alpine/git` / `node:22-alpine` | Override for air-gapped registries. |
| `cron.schedule` | `""` | When non-empty, deploy a CronJob. |
| `ttlSecondsAfterFinished` | `86400` | Job auto-cleanup after 1 day. |

## What you DON'T get

This chart deliberately does NOT include:

- **Artifact upload to S3 / GCS / Azure Blob.** Add a second container after the protect step, or pipe the report up via your existing CI artifact step. The chart focuses on running the protection cleanly — what you do with the output is a per-team decision.
- **Service / Ingress / Deployment.** JSO isn't a long-running service; it's a build step. If you find yourself wanting a Deployment here, you probably want the [hosted JSO API](https://javascriptobfuscator.com/) directly instead.

## Uninstall

```bash
helm uninstall nightly-protect
```

The created Secret (if any) goes with it. The `ttlSecondsAfterFinished` field handles automatic cleanup of completed Jobs.
