# Google Kubernetes Engine (GKE)

`deploy/gke/` is a Kustomize base for running Cyber RSS Reader on GKE with
Cloud SQL for PostgreSQL. It is a starting point to copy into your
infrastructure repository or render with your own values; nothing in it is
specific to one project.

## Architecture

```text
Users ── HTTPS ──> External Application Load Balancer (GKE Ingress)
                    ├─ Google-managed certificate, TLS policy, HTTP → HTTPS redirect
                    ├─ Cloud Armor: per-client rate limit
                    └─ Identity-Aware Proxy: only allowed Google identities
                         │ plain HTTP, from 35.191.0.0/16 and 130.211.0.0/22 only
                         ▼
        Deployment cyber-rss-api (2 replicas) ──┐
        CronJob cyber-rss-collector (every 6 h) ┼─ Cloud SQL Auth Proxy sidecar
                                                │  (IAM database auth, private IP)
                                                ▼
                                Cloud SQL for PostgreSQL 17 (no public IP)
```

- **Identity:** the Kubernetes service account `cyber-rss` is bound to the
  Google service account `cyber-rss@PROJECT_ID.iam.gserviceaccount.com` with
  Workload Identity. That account is also the Cloud SQL IAM database user, so
  there is no database password, key file or Kubernetes Secret.
- **Access:** IAP authenticates users at the load balancer. The API runs without
  `CYBER_RSS_AUTH_FILE`; a NetworkPolicy admits traffic to the API only from the
  Google load balancer ranges, so other workloads cannot bypass IAP.
- **Collection:** a CronJob runs `python -m app.worker --once` every six hours
  with `concurrencyPolicy: Forbid`. PostgreSQL advisory locks still prevent it
  from overlapping a manual collection started from the browser.
- **Hardening:** pods run as non-root with a read-only root filesystem, no
  capabilities, `RuntimeDefault` seccomp, no service account token and the
  `restricted` Pod Security Standard on the namespace. `/runtime` and `/tmp` are
  `emptyDir` volumes.
- **Egress:** DNS, the GKE metadata server, the Cloud SQL private IP, and the
  public internet on ports 80/443. Private and link-local ranges are blocked,
  which backs up the application's own SSRF checks.

## Requirements

- GKE 1.29 or later (native sidecar containers), Autopilot or Standard with
  Workload Identity Federation for GKE and Dataplane V2 / network policy
  enforcement enabled.
- A VPC with Private Services Access configured, so Cloud SQL can use a private IP.
  Private Service Connect also works: replace `--private-ip` with `--psc` in the
  proxy arguments and adjust the egress rule.
- A DNS name you control for the application.
- `gcloud`, `kubectl` and Docker.

## Values to replace

The manifests contain `REPLACE_*` placeholders. Set them once in your shell:

```bash
export PROJECT_ID=my-project
export REGION=southamerica-east1
export SQL_INSTANCE=cyber-rss
export DOMAIN=rss.example.com
export GIT_SHA=$(git rev-parse --short=12 HEAD)
# Filled in by the steps below:
export LB_IP=
export CLOUDSQL_PRIVATE_IP=

render() {
  sed -e "s/REPLACE_PROJECT_ID/$PROJECT_ID/g" -e "s/REPLACE_REGION/$REGION/g" \
      -e "s/REPLACE_SQL_INSTANCE/$SQL_INSTANCE/g" -e "s/REPLACE_DOMAIN/$DOMAIN/g" \
      -e "s/REPLACE_GIT_SHA/$GIT_SHA/g" -e "s/REPLACE_LB_IP/$LB_IP/g" \
      -e "s/REPLACE_CLOUDSQL_PRIVATE_IP/$CLOUDSQL_PRIVATE_IP/g" "$@"
}
```

| Placeholder | Meaning |
|---|---|
| `REPLACE_PROJECT_ID` | Google Cloud project ID |
| `REPLACE_REGION` | Region of the Artifact Registry repository and Cloud SQL instance |
| `REPLACE_SQL_INSTANCE` | Cloud SQL instance name |
| `REPLACE_DOMAIN` | Public DNS name for the managed certificate |
| `REPLACE_GIT_SHA` | Immutable image tag (the commit being deployed) |
| `REPLACE_LB_IP` | Global static IP of the load balancer |
| `REPLACE_CLOUDSQL_PRIVATE_IP` | Private IP of the Cloud SQL instance |

## 1. Build and publish the image

```bash
gcloud artifacts repositories create cyber-rss --repository-format=docker --location=$REGION
gcloud auth configure-docker $REGION-docker.pkg.dev
IMAGE=$REGION-docker.pkg.dev/$PROJECT_ID/cyber-rss/cyber-rss-reader:$GIT_SHA
docker build -t "$IMAGE" .
docker push "$IMAGE"
```

The cluster's node service account needs `roles/artifactregistry.reader` on the
repository. Deploy a new commit by pushing a new tag and re-rendering with that
`GIT_SHA`; never deploy `:latest`.

## 2. Cloud SQL and the database identity

```bash
gcloud sql instances create $SQL_INSTANCE \
  --database-version=POSTGRES_17 --edition=ENTERPRISE --tier=db-custom-1-3840 \
  --region=$REGION --network=projects/$PROJECT_ID/global/networks/default --no-assign-ip \
  --database-flags=cloudsql.iam_authentication=on \
  --backup-start-time=03:00 --enable-point-in-time-recovery --retained-backups-count=14 \
  --deletion-protection
gcloud sql databases create rss --instance=$SQL_INSTANCE
export CLOUDSQL_PRIVATE_IP=$(gcloud sql instances describe $SQL_INSTANCE \
  --format='value(ipAddresses[0].ipAddress)')

gcloud iam service-accounts create cyber-rss --display-name="Cyber RSS Reader"
SA=cyber-rss@$PROJECT_ID.iam.gserviceaccount.com
for role in roles/cloudsql.client roles/cloudsql.instanceUser; do
  gcloud projects add-iam-policy-binding $PROJECT_ID --member=serviceAccount:$SA --role=$role
done
gcloud iam service-accounts add-iam-policy-binding $SA --role=roles/iam.workloadIdentityUser \
  --member="serviceAccount:$PROJECT_ID.svc.id.goog[cyber-rss/cyber-rss]"
gcloud sql users create cyber-rss@$PROJECT_ID.iam --instance=$SQL_INSTANCE \
  --type=cloud_iam_service_account
```

Replace `default` with your VPC name. The Cloud SQL roles can be restricted
to this instance with an IAM condition on `resource.name`.

The application creates its own `cyber_rss` schema and runs migrations at
startup, so the IAM user needs `CREATE` on the database. Run this once as the
`postgres` user (for example in Cloud SQL Studio, after
`gcloud sql users set-password postgres --instance=$SQL_INSTANCE --prompt-for-password`):

```sql
GRANT CONNECT, CREATE ON DATABASE rss TO "cyber-rss@PROJECT_ID.iam";
```

Database backups are Cloud SQL's automated backups and point-in-time recovery;
the API's backup endpoints report that they are unsupported on PostgreSQL.

## 3. Load balancer, certificate, Cloud Armor and IAP

```bash
gcloud compute addresses create cyber-rss-ip --global
export LB_IP=$(gcloud compute addresses describe cyber-rss-ip --global --format='value(address)')
# Create a DNS A record: $DOMAIN -> $LB_IP

gcloud compute ssl-policies create cyber-rss-tls --profile=MODERN --min-tls-version=1.2

gcloud compute security-policies create cyber-rss-armor
gcloud compute security-policies rules create 1000 --security-policy=cyber-rss-armor \
  --src-ip-ranges='*' --action=throttle \
  --rate-limit-threshold-count=120 --rate-limit-threshold-interval-sec=60 \
  --conform-action=allow --exceed-action=deny-429 --enforce-on-key=IP
```

For IAP, enable `iap.googleapis.com`, configure the OAuth consent screen
(audience "Internal" for a Google Workspace organization), and grant access to
the team:

```bash
gcloud services enable iap.googleapis.com
gcloud iap web add-iam-policy-binding --role=roles/iap.httpsResourceAccessor \
  --member=group:security-team@example.com
```

This grant applies to every IAP-protected web resource in the project; use
`--resource-type=backend-services --service=<backend name>` to scope it to this
backend after the Ingress has created it. The BackendConfig enables IAP with the
Google-managed OAuth client. If your GKE version or policy requires your own
OAuth client, create it, store its ID and secret in a Kubernetes Secret, and add
`oauthclientCredentials.secretName` to the `iap` block in `backendconfig.yaml`.

## 4. Optional: import the existing SQLite archive

The import requires an empty destination, so run it before the API starts for
the first time (the API seeds the feed configuration on startup). Apply only the
prerequisites, then the import pod:

```bash
for file in namespace serviceaccount configmap networkpolicy; do
  render deploy/gke/$file.yaml | kubectl apply -f -
done
render deploy/gke/optional/import-sqlite-pod.yaml | kubectl apply -f -
kubectl -n cyber-rss wait --for=condition=Ready pod/cyber-rss-import --timeout=300s
kubectl -n cyber-rss cp data/articles.sqlite3 cyber-rss-import:/runtime/import.sqlite3 -c import
kubectl -n cyber-rss exec cyber-rss-import -c import -- \
  rss-import-postgres --sqlite /runtime/import.sqlite3 --dry-run
kubectl -n cyber-rss exec cyber-rss-import -c import -- \
  rss-import-postgres --sqlite /runtime/import.sqlite3
kubectl -n cyber-rss delete pod cyber-rss-import
```

Stop local collection before copying the archive so no articles are missed.
See [POSTGRESQL.md](POSTGRESQL.md) for what the import copies and how to roll back.

## 5. Deploy

```bash
kubectl kustomize deploy/gke | render | grep REPLACE_ && echo "Fill in every value first"
kubectl kustomize deploy/gke | render | kubectl apply -f -
kubectl -n cyber-rss rollout status deployment/cyber-rss-api
kubectl -n cyber-rss get ingress cyber-rss
kubectl -n cyber-rss get managedcertificate cyber-rss   # Active after DNS propagates
```

The certificate can take up to an hour to become `Active` after the DNS record
points to `LB_IP`. Then open `https://$DOMAIN/` and sign in with an allowed
Google account.

## Operate

```bash
# Collect now instead of waiting for the schedule
kubectl -n cyber-rss create job --from=cronjob/cyber-rss-collector collect-$(date +%s)
kubectl -n cyber-rss logs -f job/<job name> -c collector

# API logs and status
kubectl -n cyber-rss logs deployment/cyber-rss-api -c api
kubectl -n cyber-rss get pods,cronjobs,jobs
```

- **Health checks:** `/health` is public and checks database access; it backs
  the readiness probe and the load balancer health check. The liveness probe is
  a TCP check, so a database outage takes pods out of rotation without
  restarting them.
- **Caches:** the CVE lookup cache and the MISP Galaxy snapshot live in each
  pod's `emptyDir` and are rebuilt as needed. Each collector run downloads the
  MISP Galaxy update when it is due, starting from the bundled snapshot.
- **Rate limiting:** Cloud Armor enforces the per-client limit at the edge. The
  application's limiter still runs per pod as a fallback; `CYBER_RSS_TRUSTED_PROXIES`
  in the ConfigMap lets it see the real client address (see [HTTPS.md](HTTPS.md)).
- **Probes and NetworkPolicy:** on GKE, kubelet probes from the node are not
  blocked by the policies here. If your cluster's network policy enforcement
  blocks them, allow the node CIDR to port 8000 and 9090.
- **Logs:** the ConfigMap sets `CYBER_RSS_LOG_FORMAT=json`, so Cloud Logging
  shows the real severity of each API and collector line and exceptions reach
  Error Reporting. Filter with
  `resource.labels.namespace_name="cyber-rss" severity>=WARNING`.
- **Settings:** retention and other options go in `configmap.yaml`
  (see `.env.example`). Alert tokens are secrets: mount them from Secret Manager
  (for example with the Secret Manager add-on for GKE) instead of the ConfigMap.
