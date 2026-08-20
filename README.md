# Eagle Talon — Prototype

A working ASM (Attack Surface Management) prototype: a real passive-recon
scanning backend + a new console-style UI ("Talon Scope") built to navigate
hundreds/thousands of scored domains instead of scrolling a dashboard.

**Important scope note:** the scan engine only uses *passive/OSINT* techniques
— DNS, certificate-transparency logs, TLS handshake metadata, published HTTP
security headers, and RDAP registration data. No port sweeps, no intrusive
probing, no authentication attempts. That's deliberate: it's what makes it
safe to legally run against domains you don't own (suppliers, sellers,
insureds) without needing their permission first — which matters a lot for
the supply-chain / insurance / marketplace use cases in part 4.

## 1. Run the demo on your wifi (no AWS needed for this part)

```bash
# Terminal 1 — backend
cd backend
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000

# Terminal 2 — frontend
# just open frontend/index.html in a browser, or serve it:
cd frontend
python3 -m http.server 5500
# then visit http://localhost:5500
```

Open the UI, click **"+ Analyze Domain"**, and scan a real domain (e.g. one
of your own, or a willing supplier's) — that's the live path exercising DNS/
TLS/headers/crt.sh/RDAP for real. The **Scope** and **Log** views are pre-
populated with a 480-domain seeded mock portfolio so you can demo the
*scale and navigation* story (thousands of domains) without needing to
live-scan a huge list in front of a client.

To demo on a projector/other laptop over the same wifi: run backend + `python3 -m http.server`
on your machine, then have other devices hit `http://<your-laptop-ip>:5500` — no internet
or AWS required for the demo itself.

## 2. Deploy to AWS (persistent hosted version)

I can't reach AWS APIs directly from this sandboxed environment, so I
couldn't provision this in your account for you — but everything's staged
so you (or Claude Code running locally with your AWS credentials configured)
can do it in a few commands:

```bash
cd deploy
terraform init
terraform apply -var="key_name=<your-ec2-keypair>" -var="my_ip_cidr=<your.ip.here>/32"
# then, using the printed output:
scp -r ../.. ubuntu@<public_ip>:~/eagle-talon
ssh ubuntu@<public_ip> "cd eagle-talon/deploy && docker compose up -d --build"
```

This gives you one EC2 host running nginx (serving the UI) + FastAPI (the
API), reachable at `http://<public_ip>`. It's intentionally the *simplest*
path to something demoable/persistent, not a production architecture.

**When you're ready to move past prototype**, the production shape I'd
recommend is:
- **Frontend**: S3 + CloudFront (static — this UI has no build step)
- **API**: ECS Fargate behind an ALB, or Lambda + API Gateway if scan jobs
  stay short — likely a queue (SQS) + Fargate worker fleet once you're
  scanning thousands of domains on a schedule rather than on-demand
- **Data**: DynamoDB or Postgres (RDS) for scan history/trends instead of
  the in-memory store here
- **Scheduling**: EventBridge to re-scan portfolios on a cadence (daily/weekly)
- **Auth**: Cognito or your existing IdP in front of both API and UI

Happy to build that IaC out for real once you've confirmed the demo direction.

## File map

```
backend/        FastAPI app + scanner.py (real DNS/TLS/email/header/RDAP checks)
frontend/       index.html — the new "Talon Scope" UI, self-contained
deploy/         docker-compose, nginx config, Terraform for a demo EC2 host
```
