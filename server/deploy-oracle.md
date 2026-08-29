# Oracle Cloud deployment for the depwolf CVE index API

There are two deployment options. Pick the one that fits your OCI tenancy:

## Option A — OCI Compute instance (simple, recommended)

```
oci compute instance launch                       # create a VM (Ubuntu 22.04 ARM or x86)
    --availability-domain <ad>                     # e.g. Uocm:PHX-AD-1
    --image-id ocid1.image.oc1...<ubuntu-22.04>
    --shape VM.Standard.E4.Flex --shape-config '{"ocpus":2,"memoryInGBs":16}'
    --subnet-id ocid1.subnet.oc1.<your-subnet>
    --assign-public-ip true
    --ssh-authorized-keys-file ~/.ssh/id_rsa.pub
    --compartment-id ocid1.tenancy.oc1...$(oci iam compartment list -c <tenancy> --query 'data[0].id' --raw-output)
```

### 1. Upload the repo and the index

```bash
rsync -avz --exclude='.git' --exclude='__pycache__' ./ ubuntu@<instance-public-ip>:~/depwolf/
scp cpe_index.db ubuntu@<instance-public-ip>:~/depwolf/
```

### 2. On the instance

```bash
sudo apt-get update && sudo apt-get install -y python3.12 python3.12-venv
cd ~/depwolf
python3.12 -m venv .venv
.venv/bin/pip install -r server/requirements.txt
sudo mkdir -p /data && sudo mv ~/depwolf/cpe_index.db /data/cpe_index.db
```

### 3. systemd service

```
[Unit]
Description=depwolf CVE index API
After=network.target

[Service]
WorkingDirectory=/home/ubuntu/depwolf
Environment=AVIP_DB_PATH=/data/cpe_index.db
Environment=AVIP_SERVER_API_KEY=<your-secret>
ExecStart=/home/ubuntu/depwolf/.venv/bin/uvicorn server.main:app --host 0.0.0.0 --port 8000
Restart=always
User=ubuntu

[Install]
WantedBy=multi-user.target
```

```bash
sudo tee /etc/systemd/system/depwolf-api.service >/dev/null <<'EOF'
[Unit]
Description=depwolf CVE index API
After=network.target

[Service]
WorkingDirectory=/home/ubuntu/depwolf
Environment=AVIP_DB_PATH=/data/cpe_index.db
Environment=AVIP_SERVER_API_KEY=<your-secret>
ExecStart=/home/ubuntu/depwolf/.venv/bin/uvicorn server.main:app --host 0.0.0.0 --port 8000
Restart=always
User=ubuntu

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now depwolf-api
curl http://localhost:8000/healthz
```

### 4. Open the port in the OCI security list

```
oci network security-list update \
    --security-list-id ocid1.securitylist.oc1.<your-security-list> \
    --ingress-security-rules 'file://security-list-rules.json'
```

with `security-list-rules.json`:

```json
[
  {
    "protocol": "6",
    "source": "0.0.0.0/0",
    "tcpOptions": {
      "destinationPortRange": { "min": 8000, "max": 8000 }
    }
  }
]
```

> Do NOT open 8000 to the world without `AVIP_SERVER_API_KEY`. For a more
> hardened setup, put the API behind the OCI API Gateway (Option B, below).

### 5. Point the CLI at it

```bash
export AVIP_API_URL=http://<instance-public-ip>:8000
export AVIP_SERVER_API_KEY=<your-secret>   # only if the client is hardened
depwolf scan . --format table
```

## Option B — OCI API Gateway + Compute (production)

1. Deploy the service in a **private** VCN subnet (no public ingress rules).
2. Create an OCI API Gateway in front of it:
   ```
   oci api-gateway deployment create \
       --gateway-id <gateway-ocid> \
       --display-name depwolf \
       --specification file://api-gateway-spec.json
   ```
3. `api-gateway-spec.json` routes `/api/*` and `/healthz` to the compute
   instance's private IP, with a usage plan / API key.
4. CLI uses `AVIP_API_URL=https://<gateway-hostname>/api`.

## Index refresh on the server

```bash
cd ~/depwolf
.venv/bin/python -m depwolf sync         # download prebuilt
# or, from the cloud box with NVD key:
export AVIP_NVD_API_KEY=xxx
.venv/bin/python -c "from depwolf.infrastructure.cpe_index import build_index; build_index(full_sync=True)"
```

Make it a cron job to keep the index fresh:

```
0 2 * * * cd /home/ubuntu/depwolf && AVIP_DB_PATH=/data/cpe_index.db .venv/bin/python -m depwolf sync
```