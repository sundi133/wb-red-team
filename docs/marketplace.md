---
title: Cloud Marketplaces
nav_order: 12.5
---

# AWS & Azure Marketplace Guide

Red-Team AI ships as a Docker container (`Dockerfile`, `docker-compose.yml`). That means two distinct things can happen on AWS and Microsoft Azure:

1. **Deploy** — run the container on your own AWS or Azure account (single-tenant install).
2. **Publish** — list Red-Team AI on **AWS Marketplace** or **Microsoft Azure Marketplace / AppSource** so other customers can subscribe and one-click deploy it into their own accounts.

This page covers both. Pick the path you need.

---

## Part 1 — Deploy from a cloud marketplace into your own account

If you're an end user and you just want to run Red-Team AI on AWS or Azure, you have two options:

- **A. Self-deploy from the source image.** This is available today. Build the container, push to a registry, run it. Instructions below.
- **B. One-click from a published marketplace listing.** Only available once the listing in [Part 2](#part-2--publish-red-team-ai-to-a-cloud-marketplace) is approved.

### A1. Deploy to AWS (self-serve)

The image runs on any container compute. Three concrete paths, easiest first:

#### AWS App Runner (simplest)

App Runner builds and runs containers directly from a Docker image in ECR or a public registry.

```bash
# 1. Build & push the image to ECR
aws ecr create-repository --repository-name wb-red-team
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin <acct>.dkr.ecr.us-east-1.amazonaws.com

docker buildx build --platform linux/amd64 -t wb-red-team:latest --load .
docker tag wb-red-team:latest <acct>.dkr.ecr.us-east-1.amazonaws.com/wb-red-team:latest
docker push <acct>.dkr.ecr.us-east-1.amazonaws.com/wb-red-team:latest

# 2. Create the service (Console: App Runner → Create service → ECR image)
#    - Port: 4200
#    - CPU: 1 vCPU / Memory: 2 GB minimum
#    - Environment variables: ANTHROPIC_API_KEY (or your LLM key of choice),
#      DATABASE_URL, MASTER_ENCRYPTION_KEY, AUTH_MODE=dev (for first boot)
```

Pair with **Amazon RDS for PostgreSQL** for `DATABASE_URL` if you want encrypted storage and multi-user RBAC. App Runner gives you a public HTTPS URL out of the box.

#### Amazon ECS on Fargate (production)

For production deployments you'll typically want ECS Fargate + RDS + an Application Load Balancer:

1. Push the image to **ECR** (same as above).
2. Create an **RDS PostgreSQL** instance — record the connection string for `DATABASE_URL`.
3. Store `ANTHROPIC_API_KEY` and `MASTER_ENCRYPTION_KEY` in **AWS Secrets Manager**; reference them from the task definition.
4. Create an **ECS Fargate task definition** with one container, port `4200`, the env vars from [Deployment → Environment variables]({{ site.baseurl }}/deployment/#environment-variables).
5. Front it with an **Application Load Balancer** (target group on port 4200, HTTPS via ACM certificate).
6. (Optional) Add **Route 53** for a custom domain and a **CloudFront** distribution if you want global edge caching for the dashboard.

The container is stateless aside from Postgres — scale the ECS service horizontally and Postgres handles concurrency.

#### EC2 + Docker (no orchestrator)

For a single-box install — fastest to stand up, no ECS/RDS to manage:

```bash
# On an Ubuntu 22.04 EC2 instance (t3.medium or larger)
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin
git clone https://github.com/sundi133/wb-red-team.git
cd wb-red-team
cp .env.example .env   # add ANTHROPIC_API_KEY, MASTER_ENCRYPTION_KEY, etc.
sudo docker compose up -d
```

Open the security group for port `4200` (or front with nginx + Let's Encrypt for HTTPS).

### A2. Deploy to Microsoft Azure (self-serve)

Same image, three Azure paths:

#### Azure Container Apps (simplest, recommended)

Container Apps is the closest Azure equivalent of App Runner — managed, scale-to-zero, built-in HTTPS:

```bash
# 1. Push to Azure Container Registry
az acr create -g <rg> -n <acrname> --sku Basic
az acr login -n <acrname>

docker buildx build --platform linux/amd64 -t <acrname>.azurecr.io/wb-red-team:latest --load .
docker push <acrname>.azurecr.io/wb-red-team:latest

# 2. Create a Container Apps environment + app
az containerapp env create -n redteam-env -g <rg> -l eastus

az containerapp create -n wb-red-team -g <rg> \
  --environment redteam-env \
  --image <acrname>.azurecr.io/wb-red-team:latest \
  --target-port 4200 --ingress external \
  --registry-server <acrname>.azurecr.io \
  --env-vars ANTHROPIC_API_KEY=secretref:anthropic-key \
             DATABASE_URL=secretref:db-url \
             MASTER_ENCRYPTION_KEY=secretref:enc-key \
  --secrets anthropic-key=sk-ant-... db-url=postgres://... enc-key=<hex32>
```

Pair with **Azure Database for PostgreSQL — Flexible Server** for `DATABASE_URL`.

#### Azure Kubernetes Service (AKS)

For team or enterprise scale, deploy to AKS using the same manifests as the OpenShift deployment (`deploy/openshift.yaml`) with small substitutions:

- `Route` → `Ingress` (NGINX or Application Gateway Ingress Controller).
- `ImageStream` → direct image reference from ACR.
- Secrets stay as `Secret` resources (or use **Azure Key Vault CSI driver**).

```bash
az aks create -g <rg> -n redteam-aks --node-count 2 --enable-managed-identity
az aks get-credentials -g <rg> -n redteam-aks
kubectl create secret generic wb-red-team-secrets --from-env-file=.env
kubectl apply -f deploy/openshift.yaml   # edit Route → Ingress first
```

#### Azure Container Instances (one-off / dev)

The cheapest path for a single container, no orchestrator:

```bash
az container create -g <rg> -n wb-red-team \
  --image <acrname>.azurecr.io/wb-red-team:latest \
  --ports 4200 --dns-name-label wb-red-team-<unique> \
  --environment-variables AUTH_MODE=dev \
  --secure-environment-variables ANTHROPIC_API_KEY=sk-ant-...
```

ACI is best for demos and short-lived runs — for production use Container Apps or AKS.

### Cross-cloud sizing reference

| Component | Minimum | Recommended (team) | Notes |
|-----------|---------|--------------------|-------|
| App container | 1 vCPU / 2 GB | 2 vCPU / 4 GB | Scales horizontally |
| Postgres | 2 vCPU / 4 GB / 20 GB disk | 4 vCPU / 8 GB / 100 GB | Reports + audit log grow over time |
| Concurrent runs | `MAX_CONCURRENT_RUNS=10` | `MAX_CONCURRENT_RUNS=100` | LLM-bound, not CPU-bound |
| Egress | LLM provider APIs | LLM provider APIs + scan targets | Allow outbound HTTPS |

---

## Part 2 — Publish Red-Team AI to a cloud marketplace

This section is for vendors / maintainers who want a public marketplace listing so other AWS / Azure customers can subscribe with one click. The work is mostly **packaging, paperwork, and security review** — the container itself is unchanged.

### B1. Publish to AWS Marketplace

AWS Marketplace supports several product types. For Red-Team AI the right one is a **Container Product** (since we ship a Docker image), with **AMI** as a fallback option for customers who prefer a VM.

**High-level flow:**

1. **Become a seller.** Register at [AWS Marketplace Management Portal](https://aws.amazon.com/marketplace/management/) — requires a tax/banking profile (W-9/W-8 + bank for payouts) and a public-facing legal entity. This is gated and can take 1–3 business days.
2. **Choose a delivery option:**
   - **Container Product → ECS / EKS / Fargate.** Customers launch a CloudFormation template that pulls our image from an AWS-hosted ECR repository.
   - **Container Product → Helm chart.** For EKS-first customers.
   - **AMI Product.** For customers who want a single VM — we build an Ubuntu AMI with the container pre-installed.
3. **Choose a pricing model:**
   - **BYOL (Bring Your Own License)** — free on Marketplace, customer brings their own LLM keys. Simplest first listing.
   - **Hourly / Annual** — Marketplace charges customers per hour or per year of the running task.
   - **SaaS Contracts / SaaS Subscriptions** — customer pays AWS, we host. Requires integrating the [AWS Marketplace Metering Service](https://docs.aws.amazon.com/marketplace/latest/userguide/metering-service.html).
4. **Build the deliverable:**
   - For a **Container Product**: push `wb-red-team:<version>` to the AWS-Marketplace-provided ECR repository, write a **CloudFormation launch template** that wires up ECS Fargate + RDS + ALB, and a **usage instructions** doc.
   - For an **AMI Product**: build an AMI from `ami-amazon-linux-2023` with Docker + the wb-red-team image + a systemd unit. Share it with the AWS Marketplace AMI scanning account.
5. **Submit for review.** AWS runs a security scan (port exposure, default credentials, OS CVEs). Expect 5–10 business days. Common rejections: default passwords, world-readable secrets in the AMI, root SSH enabled. Our image already has none of these — but double-check `AUTH_MODE` is **not** `dev` in the marketplace build.
6. **Publish.** Once approved, customers can find the listing at `aws.amazon.com/marketplace` and subscribe.

**Repo artifacts to add when we pursue this:**

- `deploy/aws-marketplace/cloudformation.yaml` — single-click launch template (ECS Fargate + RDS + ALB).
- `deploy/aws-marketplace/usage-instructions.md` — post-launch setup (LLM keys, first admin user, dashboard URL).
- `deploy/aws-marketplace/architecture.png` — required for the listing page.
- A hardened `Dockerfile.marketplace` if we want a separately tagged image with no `AUTH_MODE=dev` fallback.

**Useful links:**

- [AWS Marketplace seller guide](https://docs.aws.amazon.com/marketplace/latest/userguide/user-guide-for-sellers.html)
- [Container product checklist](https://docs.aws.amazon.com/marketplace/latest/userguide/container-product-getting-started.html)
- [AMI product checklist](https://docs.aws.amazon.com/marketplace/latest/userguide/ami-products.html)

### B2. Publish to Microsoft Azure Marketplace

Azure has two related storefronts:

- **Azure Marketplace** — IT-buyer focused, sells infra and platform products (VMs, containers, managed apps, SaaS).
- **Microsoft AppSource** — business-buyer focused, sells line-of-business SaaS apps.

For Red-Team AI the right venue is **Azure Marketplace**, published as one of:

- **Azure Container Offer** — image pulled from a Microsoft-managed registry into the customer's AKS / Container Apps.
- **Azure Application (Managed App)** — ARM/Bicep template that deploys the full stack (Container Apps + Postgres + Key Vault) into the customer's subscription, optionally as a *managed* app where we retain operator access.
- **SaaS Offer** — we host, customer pays Microsoft, Microsoft pays us. Requires integrating [Marketplace SaaS Fulfillment APIs](https://learn.microsoft.com/en-us/azure/marketplace/partner-center-portal/pc-saas-fulfillment-api-v2).
- **Virtual Machine Offer** — Ubuntu VHD with the container pre-installed (the analogue of an AWS AMI).

**High-level flow:**

1. **Become a publisher.** Enroll in [Microsoft Partner Center](https://partner.microsoft.com/) under the **Commercial Marketplace** program. Requires a [verified employment / company identity](https://learn.microsoft.com/en-us/azure/marketplace/create-account) and a tax/payout profile. Allow 3–5 business days.
2. **Pick an offer type** from the list above. For a first listing, the **Azure Application (Managed App)** is the most flexible — we ship a Bicep/ARM template and Microsoft handles the deploy UX.
3. **Choose a plan / pricing model:**
   - **BYOL** (free, customer brings LLM keys).
   - **Per-core hour** or **Per-month flat** via Azure billing.
   - **Private plan** — only visible to specific customer tenant IDs (great for design partners before public GA).
4. **Build the deliverable:**
   - For **Azure Application**: `deploy/azure-marketplace/mainTemplate.json` (ARM) + `createUiDefinition.json` (the form the customer sees in the Portal). Zip both and upload as the offer's technical asset.
   - For **Container Offer**: push the image to an ACR that Microsoft mirrors into their marketplace registry.
   - For **VM Offer**: build a [Marketplace-approved Ubuntu VHD](https://learn.microsoft.com/en-us/azure/marketplace/marketplace-virtual-machines) with the container preinstalled, generalize with `waagent -deprovision+user`, share via SAS URI.
5. **Submit for certification.** Microsoft runs automated and manual review: VM image security scan, ARM template validation, listing copy review, screenshots, support contact verification. Expect 7–14 business days; expect at least one round of revisions.
6. **Go live.** Use a **preview audience** (a list of tenant IDs) to soft-launch, then promote to public.

**Repo artifacts to add when we pursue this:**

- `deploy/azure-marketplace/mainTemplate.json` — ARM template: Container Apps + Postgres Flexible Server + Key Vault + Log Analytics.
- `deploy/azure-marketplace/createUiDefinition.json` — Portal form for LLM key, admin email, instance size.
- `deploy/azure-marketplace/marketplace-listing.md` — store description, screenshots, support URL.
- `deploy/azure-marketplace/viewDefinition.json` (only for Managed Apps) — operator dashboard inside the customer's subscription.

**Useful links:**

- [Azure Marketplace publisher guide](https://learn.microsoft.com/en-us/azure/marketplace/overview)
- [Plan an Azure Application offer](https://learn.microsoft.com/en-us/azure/marketplace/plan-azure-application-offer)
- [Plan a Container offer](https://learn.microsoft.com/en-us/azure/marketplace/plan-azure-container-offer)
- [SaaS fulfillment API](https://learn.microsoft.com/en-us/azure/marketplace/partner-center-portal/pc-saas-fulfillment-api-v2)

### Listing prerequisites that apply to both clouds

Both marketplaces require, at minimum:

- A **public support contact** (email + SLA statement).
- A **privacy policy** and **EULA / terms of service** URL.
- **Listing screenshots** of the dashboard, a sample report, and the run UI.
- **A security overview** describing the encryption-at-rest design (`MASTER_ENCRYPTION_KEY`, AES-256-GCM envelope encryption — see [Deployment]({{ site.baseurl }}/deployment/)) and how customer LLM keys are stored.
- A **versioning policy** (we already use [CHANGELOG.md](https://github.com/sundi133/wb-red-team/blob/main/CHANGELOG.md) — link it from the listing).
- **No default credentials.** Our marketplace build must not ship with `AUTH_MODE=dev`; the deploy template should require the customer to choose an OIDC provider or set an initial admin email.

---

## Status & next steps

| Path | Status today |
|------|--------------|
| Self-deploy on AWS (App Runner / ECS / EC2) | **Supported.** Use the image from this repo. |
| Self-deploy on Azure (Container Apps / AKS / ACI) | **Supported.** Use the image from this repo. |
| Published AWS Marketplace listing | **Not yet published.** Tracked under [Part 2 → B1](#b1-publish-to-aws-marketplace). |
| Published Azure Marketplace listing | **Not yet published.** Tracked under [Part 2 → B2](#b2-publish-to-azure-marketplace). |

If you want a one-click marketplace launch and the listing doesn't exist yet, please open an issue on [GitHub](https://github.com/sundi133/wb-red-team/issues) — we prioritize the listings with the most customer demand first.
