# 🧪 CI/CD AUTOMATION LAB GUIDE

## Enterprise GitOps Pipeline with Jenkins + Flux CD on AKS

✅ Vault | ✅ Nexus | ✅ OPA/Gatekeeper | ✅ Hybrid RHEL/Windows VMs | ✅ 21+ Tools

---

## 🎯 OBJECTIVE

Automate 95%+ of an enterprise-grade CI/CD pipeline using:

- **CI**: Jenkins
- **CD**: Flux CD (GitOps) on Azure Kubernetes Service (AKS)
- **Security**: Vault (secrets), Trivy (image scan), SonarQube (code scan), OPA/Gatekeeper (policy)
- **Artifact**: Nexus Repository (replaces ACR)
- **Observability**: Prometheus + Grafana + Alertmanager
- **Infra**: Terraform, Ansible, Azure CLI
- **Hybrid**: RHEL + Windows VMs as Jenkins agents + monitoring targets

---

## 🧰 PREREQUISITES

### ✅ Tools & Accounts

| Tool | Purpose | Install Command |
|------|---------|-----------------|
| Azure CLI | Provision AKS, VMs | `curl -sL https://aka.ms/InstallAzureCLIDeb \| sudo bash` |
| kubectl | Control Kubernetes | `az aks install-cli` |
| Helm | Deploy apps | [Install Helm](https://helm.sh/docs/intro/install/) |
| Flux CLI | GitOps sync | `curl -s https://fluxcd.io/install.sh \| sudo bash` |
| Terraform | IaC | [Download](https://developer.hashicorp.com/terraform/downloads) |
| Ansible | Configure VMs | `pip3 install ansible` |
| Docker | Build images | [Install Docker](https://docs.docker.com/get-docker/) |
| Trivy | Image scan | `brew install aquasecurity/trivy/trivy` or `sudo apt install trivy` |

> 💡 Use **WSL2 on Windows** for best experience.

---

## 🔧 STEP-BY-STEP SETUP

> ⚠️ **Follow this order exactly** — skipping steps will cause failures.

---

### ✅ STEP 1: LOGIN TO AZURE & SET CONTEXT

```bash
az login
az account set --subscription YOUR_SUBSCRIPTION_ID
```

---

## ✅ STEP 2: PROVISION INFRASTRUCTURE WITH TERRAFORM

```bash
cd terraform/
terraform init
terraform apply -auto-approve
```

> ✅ Creates: AKS cluster, RHEL VM, Windows VM, VNet

---

### ✅ STEP 3: CONNECT TO AKS

```bash
az aks get-credentials --name myAKSCluster --resource-group ci-cd-lab-rg
kubectl get nodes  # ← MUST show nodes
```

> ❌ If this fails → fix kubeconfig before proceeding.

---

### ✅ STEP 4: DEPLOY VAULT

```bash
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault --set "server.dev.enabled=true" -n vault --create-namespace

# Wait for pod
kubectl wait --for=condition=ready pod/vault-0 -n vault --timeout=120s

# Port-forward (keep running in background)
kubectl port-forward svc/vault 8200:8200 -n vault &
```

> 🌐 Access Vault UI: [http://localhost:8200](http://localhost:8200) → root token: `root`

---

### ✅ STEP 5: INITIALIZE VAULT

```bash
./vault/setup-vault.sh
```

> ✅ Sets up secrets, policy, Kubernetes auth.

---

### ✅ STEP 6: DEPLOY NEXUS

```bash
helm repo add sonatype https://sonatype.github.io/helm3-charts/
helm install nexus sonatype/nexus-repository-manager \
  --set persistence.enabled=true \
  --set service.type=LoadBalancer \
  -n nexus --create-namespace

# Get external IP
kubectl get svc nexus-nexus-repository-manager -n nexus -w
```

> 🌐 Access Nexus: `http://<EXTERNAL_IP>:8081` → admin / auto-generated password

---

### ✅ STEP 7: INSTALL OPA/GATEKEEPER

```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.10/deploy/gatekeeper.yaml
kubectl wait --for=condition=available --timeout=300s -n gatekeeper-system deployment/gatekeeper-controller-manager

# Apply policies
kubectl apply -f policies/
```

> ✅ Enforces: no “latest” tag, requires CPU/memory limits

---

### ✅ STEP 8: DEPLOY JENKINS + PROMETHEUS

```bash
# Jenkins
helm repo add jenkins https://charts.jenkins.io
helm install jenkins jenkins/jenkins -n jenkins --create-namespace --set serviceType=LoadBalancer

# Get password
kubectl exec --namespace jenkins -it svc/jenkins -c jenkins -- /bin/cat /run/secrets/chart-admin-password

# Prometheus + Grafana
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack -n monitoring --create-namespace
```

> 🌐 Access Jenkins: `kubectl port-forward svc/jenkins 8080:8080 -n jenkins` → [http://localhost:8080](http://localhost:8080)  
> 🌐 Access Grafana: `kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring` → admin / prom-operator

---

### ✅ STEP 9: CONFIGURE VMs WITH ANSIBLE

#### ➤ 9.1 Update Inventory Files

Edit these files with your VM public IPs:

```bash
nano ansible/inventory/azure_rhel_hosts.ini     # Replace <PUBLIC_IP>
nano ansible/inventory/azure_windows_hosts.ini  # Replace IPs + password
```

#### ➤ 9.2 Run Playbooks

```bash
ansible-playbook -i ansible/inventory/azure_rhel_hosts.ini ansible/playbooks/setup_rhel_agent.yml
ansible-playbook -i ansible/inventory/azure_windows_hosts.ini ansible/playbooks/setup_windows_agent.yml
```

> ✅ Installs: Jenkins agent, Node Exporter (RHEL), Windows Exporter (Win)

---

### ✅ STEP 10: BOOTSTRAP FLUX CD

```bash
./scripts/deploy-with-flux.sh
```

> ⚠️ Update `yourname` and `gitops-repo` in the script first!

---

### ✅ STEP 11: TRIGGER PIPELINE

1. Commit and push your code:

```bash
git add .
git commit -m "Trigger CI/CD pipeline"
git push origin main
```

1. Jenkins auto-triggers → builds → scans → pushes to Nexus → updates GitOps repo → Flux deploys to AKS.

---

## ✅ VALIDATION & TESTING

### 🔍 Check Deployment

```bash
kubectl get pods -w
kubectl get svc myapp-service
curl http://<EXTERNAL_IP>
```

### 🔍 Verify Vault Secret Injection

```bash
kubectl exec deploy/myapp-app -- env | grep DB_PASSWORD
# Should show: DB_PASSWORD=supersecret123
```

### 🔍 Test OPA Policy

Try to deploy a pod with “latest” tag or no limits — it should be blocked:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: bad-pod
spec:
  containers:
  - name: nginx
    image: nginx:latest
EOF
```

> ❌ Should fail with OPA policy violation message.

### 🔍 Check Prometheus Targets

```bash
kubectl port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090 -n monitoring
```

> 🌐 Visit <http://localhost:9090/targets> → should see `node-exporter` (RHEL) and `windows-exporter` (Windows VM)

---

## 🛠️ TROUBLESHOOTING

| Symptom | Solution |
|---------|----------|
| `Kubernetes cluster unreachable` | Run `az aks get-credentials` → verify with `kubectl get nodes` |
| Helm install fails | Ensure `kubectl` context points to AKS, not local cluster |
| Flux not syncing | Check `flux get kustomizations -A`, verify Git repo path/branch |
| ImagePullBackOff | Ensure Nexus is running, AKS has pull permissions, tag exists |
| Windows VM not reachable | Verify WinRM enabled, NSG allows 5986, correct password |

---

## 🎓 LEARNING OUTCOMES

By completing this lab, you have demonstrated mastery of:

- ✅ Infrastructure as Code (Terraform)
- ✅ CI/CD Pipeline Design (Jenkins)
- ✅ GitOps Principles (Flux CD)
- ✅ Kubernetes Application Deployment (Helm)
- ✅ Container Security (Trivy, SonarQube)
- ✅ Secrets Management (Vault)
- ✅ Policy as Code (OPA/Gatekeeper)
- ✅ Observability Stack (Prometheus, Grafana)
- ✅ Configuration Management (Ansible)
- ✅ Hybrid Cloud Environments (Azure + VMs)
- ✅ Automation & Toolchain Integration (21+ tools.

---
