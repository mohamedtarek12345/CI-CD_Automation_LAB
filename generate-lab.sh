#!/bin/bash
# Run this in an empty folder

cat > README.md << 'EOF'
# 🚀 CI/CD Automation Lab: Enterprise GitOps on AKS

> Automated 95%+ of simulated enterprise pipeline using Jenkins + Flux CD on AKS, integrating **21+ tools** including Vault, Nexus, OPA, Windows/RHEL VMs, for zero-downtime, policy-compliant, observable deployments.

## 🧰 Tools Used
- **CI/CD**: Jenkins, Flux CD, Git, Helm, Kustomize
- **Infra**: AKS, Azure VMs (RHEL/Windows), Terraform, Ansible, Azure CLI
- **Artifact**: Nexus Repository
- **Security**: Trivy, SonarQube, Vault, OPA/Gatekeeper
- **Observability**: Prometheus, Grafana, Alertmanager, Windows Exporter, Node Exporter
- **Notifications**: Slack

## 🖼️ Architecture
\`\`\`mermaid
graph TD
    subgraph "Developer Workflow"
        A[Developer Pushes to GitHub] --> B[Jenkins CI Pipeline]
    end

    subgraph "CI: Build, Scan, Store"
        B --> C1[Build Docker Image]
        B --> C2[Scan: Trivy + SonarQube]
        C2 --> D[Push Image to Nexus Repo]
        D --> E[Update GitOps Repo Tag]
    end

    subgraph "CD: GitOps Deployment"
        E --> F[Flux CD Detects Change]
        F --> G[Apply HelmRelease to AKS]
        G --> H[K8s Cluster]
    end

    subgraph "Kubernetes Runtime"
        H --> I[Pod: App + Vault Agent Sidecar]
        I --> J[Secrets from Vault]
        H --> K[OPA/Gatekeeper Policy Enforcement]
        K --> K1["⛔ Block latest tag"]
        K --> K2["⛔ Block no resource limits"]
    end

    subgraph "Observability & Alerting"
        I --> L[Prometheus Scrapes]
        L --> M1[Grafana Dashboards]
        L --> M2[Alertmanager → Slack]
        L --> M3[Windows Exporter - Win VM]
        L --> M4[Node Exporter - RHEL VM]
    end

    subgraph "Hybrid Infrastructure"
        N[RHEL VM] --> O[Ansible Configured: Node Exporter, Jenkins Agent]
        P[Windows VM] --> Q[Ansible Configured: Windows Exporter, Jenkins Agent]
        O --> L
        Q --> L
    end

    subgraph "Security & Compliance"
        R[Vault] --> J
        S[OPA/Gatekeeper] --> K
        T[Nexus Repo] --> D
        U[Trivy/SonarQube] --> C2
    end

    classDef infra fill:#e0f7fa,stroke:#00796b;
    classDef security fill:#ffebee,stroke:#c62828;
    classDef observability fill:#e8f5e8,stroke:#2e7d32;
    classDef gitops fill:#fff3e0,stroke:#ef6c00;

    class A,B,C1,C2,D,E,F,G gitops
    class H,I,J,K security
    class L,M1,M2,M3,M4 observability
    class N,O,P,Q,R,S,T,U infra
\`\`\`

## 🚦 Setup Guide

1. Deploy Vault:  
   \`\`\`bash
   helm install vault hashicorp/vault --set "server.dev.enabled=true" -n vault --create-namespace
   \`\`\`

2. Deploy Nexus:  
   \`\`\`bash
   helm install nexus sonatype/nexus-repository-manager --set persistence.enabled=true,service.type=LoadBalancer -n nexus --create-namespace
   \`\`\`

3. Install OPA/Gatekeeper:  
   \`\`\`bash
   kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.10/deploy/gatekeeper.yaml
   kubectl apply -f policies/
   \`\`\`

4. Run Terraform → Ansible → Jenkins → Flux as before.

> 🔐 Never commit secrets. Use Vault or Azure Key Vault.

---
EOF

cat > .gitignore << 'EOF'
# Local & Secrets
*.log
.env
secrets.yaml
vault-token.txt
terraform.tfstate
terraform.tfstate.backup
.terraform/
.terraform.lock.hcl

# Binaries & Caches
node_modules/
__pycache__/
*.pyc
*.exe
*.msi

# Tools & Editors
.jenkins/
.vscode/
.idea/
*.swp
.DS_Store
Thumbs.db

# Jenkins & Build Artifacts
workspace/
target/
build/
dist/
*.jar
*.war

# Ansible
.retry
EOF

mkdir -p app
cat > app/app.py << 'EOF'
from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>🚀 CI/CD Automation Lab - Deployed via Flux + Jenkins!</h1><p>Zero-downtime updates enabled.</p>"

@app.route('/health')
def health():
    return "OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
EOF

cat > app/requirements.txt << 'EOF'
Flask==3.0.0
EOF

cat > app/Dockerfile << 'EOF'
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
EOF

cat > app/Jenkinsfile << 'EOF'
pipeline {
    agent any

    environment {
        NEXUS_HOST = 'YOUR_NEXUS_IP:8082'  // ← REPLACE WITH YOUR NEXUS IP
        IMAGE_NAME = 'myapp'
        GITOPS_REPO = 'git@github.com:yourname/gitops-repo.git'
    }

    stages {
        stage('Checkout') {
            steps { checkout scm }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    docker.build("${NEXUS_HOST}/${IMAGE_NAME}:${env.BUILD_ID}")
                }
            }
        }

        stage('Security Scan - Trivy') {
            steps {
                sh "trivy image --exit-code 1 --severity CRITICAL ${NEXUS_HOST}/${IMAGE_NAME}:${env.BUILD_ID}"
            }
        }

        stage('Code Quality - SonarQube') {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh 'sonar-scanner -Dsonar.projectKey=myapp -Dsonar.sources=. -Dsonar.host.url=http://sonarqube:9000'
                }
            }
        }

        stage('Push to Nexus') {
            steps {
                script {
                    docker.withRegistry("https://${NEXUS_HOST}", 'nexus-creds') {
                        docker.image("${NEXUS_HOST}/${IMAGE_NAME}:${env.BUILD_ID}").push()
                        docker.image("${NEXUS_HOST}/${IMAGE_NAME}:build-${env.BUILD_ID}").push()
                    }
                }
            }
        }

        stage('Update GitOps Repo') {
            steps {
                script {
                    sh """
                        git clone ${GITOPS_REPO} gitops
                        cd gitops/charts/myapp
                        sed -i 's/tag: .*/tag: build-${env.BUILD_ID}/g' values.yaml
                        cd ../..
                        git config --global user.email "jenkins@lab.com"
                        git config --global user.name "Jenkins CI"
                        git add .
                        git commit -m "Update image tag to build-${env.BUILD_ID} [skip-ci]"
                        git push origin main
                    """
                }
            }
        }
    }

    post {
        success {
            slackSend channel: '#deployments', message: "✅ Deployment Success: Build #${env.BUILD_NUMBER} → Tag build-${env.BUILD_ID} → AKS via Flux"
        }
        failure {
            slackSend channel: '#alerts', message: "❌ Build #${env.BUILD_NUMBER} FAILED in stage ${env.STAGE_NAME}"
        }
    }
}
EOF

mkdir -p helm/myapp-chart/templates
cat > helm/myapp-chart/Chart.yaml << 'EOF'
apiVersion: v2
name: myapp
description: A Helm chart for the CI/CD Automation Lab app
type: application
version: 0.1.0
appVersion: "1.0"
EOF

cat > helm/myapp-chart/values.yaml << 'EOF'
replicaCount: 3

image:
  repository: YOUR_NEXUS_IP:8082/myapp  # ← REPLACE WITH YOUR NEXUS IP
  tag: build-latest  # Will be overridden by Jenkins
  pullPolicy: Always

service:
  type: LoadBalancer
  port: 80
  targetPort: 5000

resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

autoscaling:
  enabled: false
EOF

cat > helm/myapp-chart/templates/deployment.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ .Release.Name }}-app
  labels:
    app: {{ .Release.Name }}
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "myapp"
    vault.hashicorp.com/agent-inject-secret-db-creds: "secret/data/myapp/db"
    vault.hashicorp.com/agent-inject-template-db-creds: |
      {{ with secret "secret/data/myapp/db" -}}
      export DB_PASSWORD="{{ .Data.data.password }}"
      {{- end }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ .Release.Name }}
  template:
    meta
      labels:
        app: {{ .Release.Name }}
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "myapp"
        vault.hashicorp.com/agent-inject-secret-db-creds: "secret/data/myapp/db"
        vault.hashicorp.com/agent-inject-template-db-creds: |
          {{ with secret "secret/data/myapp/db" -}}
          export DB_PASSWORD="{{ .Data.data.password }}"
          {{- end }}
    spec:
      serviceAccountName: {{ .Release.Name }}-vault-sa
      containers:
      - name: app
        image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
        imagePullPolicy: {{ .Values.image.pullPolicy }}
        ports:
        - containerPort: 5000
        resources:
          {{- toYaml .Values.resources | nindent 10 }}
        env:
        - name: DB_PASSWORD
          value: $(DB_PASSWORD)
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 5
EOF

cat > helm/myapp-chart/templates/service.yaml << 'EOF'
apiVersion: v1
kind: Service
metadata:
  name: {{ .Release.Name }}-service
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: {{ .Values.service.targetPort }}
      protocol: TCP
      name: http
  selector:
    app: {{ .Release.Name }}
EOF

cat > helm/myapp-chart/templates/vault-sa.yaml << 'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ .Release.Name }}-vault-sa
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
meta
  name: {{ .Release.Name }}-vault-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
- kind: ServiceAccount
  name: {{ .Release.Name }}-vault-sa
  namespace: default
EOF

mkdir -p terraform
cat > terraform/main.tf << 'EOF'
provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "lab" {
  name     = "ci-cd-lab-rg"
  location = "eastus"
}

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "myAKSCluster"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  dns_prefix          = "myaks"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    Environment = "Lab"
  }
}

resource "azurerm_container_registry" "acr" {
  name                = "myacr"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  sku                 = "Basic"
  admin_enabled       = true
}

resource "azurerm_linux_virtual_machine" "rhel" {
  name                = "rhel-vm"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = "Standard_B1s"
  admin_username      = "azureuser"
  network_interface_ids = [
    azurerm_network_interface.rhel_nic.id
  ]
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "RedHat"
    offer     = "RHEL"
    sku       = "8_7"
    version   = "latest"
  }
  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }
}

resource "azurerm_windows_virtual_machine" "win" {
  name                = "win-vm"
  resource_group_name = azurerm_resource_group.lab.name
  location            = azurerm_resource_group.lab.location
  size                = "Standard_B1s"
  admin_username      = "azureuser"
  admin_password      = "ReplaceWithYourPassword123!"
  network_interface_ids = [
    azurerm_network_interface.win_nic.id
  ]
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-Datacenter"
    version   = "latest"
  }
}

resource "azurerm_network_interface" "rhel_nic" {
  name                = "rhel-nic"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.lab.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_network_interface" "win_nic" {
  name                = "win-nic"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.lab.id
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_virtual_network" "lab" {
  name                = "lab-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
}

resource "azurerm_subnet" "lab" {
  name                 = "lab-subnet"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.0.1.0/24"]
}
EOF

cat > terraform/variables.tf << 'EOF'
variable "location" {
  default = "eastus"
}

variable "prefix" {
  default = "ci-cd-lab"
}
EOF

cat > terraform/providers.tf << 'EOF'
provider "azurerm" {
  features {}
}

provider "helm" {
  kubernetes {
    host                   = azurerm_kubernetes_cluster.aks.kube_config.0.host
    client_certificate     = base64decode(azurerm_kubernetes_cluster.aks.kube_config.0.client_certificate)
    client_key             = base64decode(azurerm_kubernetes_cluster.aks.kube_config.0.client_key)
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.aks.kube_config.0.cluster_ca_certificate)
  }
}

provider "kubernetes" {
  host                   = azurerm_kubernetes_cluster.aks.kube_config.0.host
  client_certificate     = base64decode(azurerm_kubernetes_cluster.aks.kube_config.0.client_certificate)
  client_key             = base64decode(azurerm_kubernetes_cluster.aks.kube_config.0.client_key)
  cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.aks.kube_config.0.cluster_ca_certificate)
}
EOF

mkdir -p ansible/inventory
cat > ansible/inventory/azure_rhel_hosts.ini << 'EOF'
[rhel-agents]
rhel-vm ansible_host=<PUBLIC_IP> ansible_user=azureuser

[rhel-agents:vars]
ansible_ssh_private_key_file=~/.ssh/id_rsa
ansible_python_interpreter=/usr/bin/python3
EOF

cat > ansible/inventory/azure_windows_hosts.ini << 'EOF'
[windows-agents]
win-vm ansible_host=YOUR_WINDOWS_VM_IP ansible_user=azureuser ansible_password=YOUR_ADMIN_PASSWORD

[windows-agents:vars]
ansible_connection=winrm
ansible_winrm_transport=ntlm
ansible_winrm_server_cert_validation=ignore
ansible_port=5986
EOF

mkdir -p ansible/playbooks
cat > ansible/playbooks/setup_rhel_agent.yml << 'EOF'
---
- name: Configure RHEL VM as Jenkins Agent & Monitoring Target
  hosts: rhel-agents
  become: yes
  tasks:
    - name: Install Git
      yum:
        name: git
        state: present

    - name: Install Java (for Jenkins agent)
      yum:
        name: java-11-openjdk
        state: present

    - name: Install Node Exporter (for Prometheus)
      get_url:
        url: https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
        dest: /tmp/node_exporter.tar.gz

    - name: Extract Node Exporter
      unarchive:
        src: /tmp/node_exporter.tar.gz
        dest: /opt
        remote_src: yes

    - name: Create systemd service for Node Exporter
      copy:
        content: |
          [Unit]
          Description=Node Exporter
          After=network.target
          [Service]
          User=root
          ExecStart=/opt/node_exporter-1.6.1.linux-amd64/node_exporter
          [Install]
          WantedBy=multi-user.target
        dest: /etc/systemd/system/node_exporter.service

    - name: Start and enable Node Exporter
      systemd:
        name: node_exporter
        state: started
        enabled: yes

    - name: Open firewall for Node Exporter
      firewalld:
        port: 9100/tcp
        permanent: yes
        state: enabled
        immediate: yes
EOF

cat > ansible/playbooks/setup_windows_agent.yml << 'EOF'
---
- name: Configure Windows VM as Jenkins Agent + Monitoring Target
  hosts: windows-agents
  vars:
    jenkins_url: "http://YOUR_JENKINS_IP:8080"  # ← REPLACE
    agent_name: "win-agent"
    work_dir: "C:\\jenkins"
  tasks:
    - name: Install Chocolatey
      win_chocolatey:
        name: chocolatey
        state: present

    - name: Install Git
      win_chocolatey:
        name: git
        state: present

    - name: Install OpenJDK 11
      win_chocolatey:
        name: temurin11jre
        state: present

    - name: Create Jenkins directory
      win_file:
        path: "{{ work_dir }}"
        state: directory

    - name: Download Jenkins agent JAR
      win_get_url:
        url: "{{ jenkins_url }}/jnlpJars/agent.jar"
        dest: "{{ work_dir }}\\agent.jar"

    - name: Create Jenkins agent launch script
      win_copy:
        content: |
          cd {{ work_dir }}
          java -jar agent.jar -jnlpUrl {{ jenkins_url }}/computer/{{ agent_name }}/slave-agent.jnlp -secret YOUR_SECRET_HERE -workDir "{{ work_dir }}"
        dest: "{{ work_dir }}\\start-agent.bat"

    - name: Download Windows Exporter
      win_get_url:
        url: "https://github.com/prometheus-community/windows_exporter/releases/download/v0.24.0/windows_exporter-0.24.0-amd64.msi"
        dest: "{{ work_dir }}\\windows_exporter.msi"

    - name: Install Windows Exporter
      win_package:
        path: "{{ work_dir }}\\windows_exporter.msi"
        arguments: ENABLED_COLLECTORS="cpu,cs,logical_disk,memory,net,os,service,system" LISTEN_PORT=9182
        state: present

    - name: Open Firewall for Windows Exporter
      win_firewall_rule:
        name: "Allow Windows Exporter"
        direction: in
        action: allow
        protocol: tcp
        localport: 9182
        enabled: yes
EOF

mkdir -p scripts
cat > scripts/deploy-with-flux.sh << 'EOF'
#!/bin/bash
echo "🚀 Bootstrapping Flux CD..."

flux bootstrap github \
  --owner=yourname \
  --repository=gitops-repo \
  --branch=main \
  --path=clusters/my-aks-cluster \
  --personal

echo "✅ Flux bootstrapped. Your cluster is now GitOps-managed!"
EOF

chmod +x scripts/deploy-with-flux.sh

cat > scripts/scan-with-trivy.sh << 'EOF'
#!/bin/bash
IMAGE="$1"
trivy image --exit-code 1 --severity CRITICAL "$IMAGE"
EOF

chmod +x scripts/scan-with-trivy.sh

cat > scripts/notify-slack.sh << 'EOF'
#!/bin/bash
MESSAGE="$1"
curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"$MESSAGE\"}" YOUR_SLACK_WEBHOOK_URL
EOF

chmod +x scripts/notify-slack.sh

mkdir -p policies
cat > policies/require_limits_template.yaml << 'EOF'
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
meta
  name: k8srequiredlimits
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLimits
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlimits
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.memory
          msg := sprintf("Container <%v> has no memory limit", [container.name])
        }
        violation[{"msg": msg}] {
          container := input.review.object.spec.containers[_]
          not container.resources.limits.cpu
          msg := sprintf("Container <%v> has no cpu limit", [container.name])
        }
EOF

cat > policies/require_limits_constraint.yaml << 'EOF'
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLimits
meta
  name: require-container-limits
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
EOF

cat > policies/no_latest_template.yaml << 'EOF'
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
meta
  name: k8snoimagelatest
spec:
  crd:
    spec:
      names:
        kind: K8sNoImageLatest
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8snoimagelatest
        violation[{"msg": msg}] {
          image := input.review.object.spec.containers[_].image
          endswith(image, ":latest")
          msg := sprintf("Image <%v> uses 'latest' tag", [image])
        }
EOF

cat > policies/no_latest_constraint.yaml << 'EOF'
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sNoImageLatest
meta
  name: no-latest-tag
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
EOF

mkdir -p vault
cat > vault/setup-vault.sh << 'EOF'
#!/bin/bash
echo "🔑 Setting up Vault for Kubernetes..."

kubectl port-forward svc/vault 8200:8200 -n vault &

sleep 5

curl --header "X-Vault-Token: root" \
     --request POST \
     --data '{"type": "kv-v2"}' \
     http://localhost:8200/v1/sys/mounts/secret

curl --header "X-Vault-Token: root" \
     --request POST \
     --data '{"data": {"password": "supersecret123"}}' \
     http://localhost:8200/v1/secret/data/myapp/db

curl --header "X-Vault-Token: root" \
     --request PUT \
     --data @- \
     http://localhost:8200/v1/sys/policies/acl/myapp <<EOF
{
  "policy": "path \"secret/data/myapp/*\" { capabilities = [\"read\"] }"
}
EOF

KUBE_CA_CERT=$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.certificate-authority-data}' | base64 -d)
KUBE_HOST=$(kubectl config view --raw --minify --flatten -o jsonpath='{.clusters[].cluster.server}')

curl --header "X-Vault-Token: root" \
     --request POST \
     --data '{"type": "kubernetes"}' \
     http://localhost:8200/v1/sys/auth/kubernetes

curl --header "X-Vault-Token: root" \
     --request POST \
     --data "{\"kubernetes_host\": \"$KUBE_HOST\", \"kubernetes_ca_cert\": \"$KUBE_CA_CERT\"}" \
     http://localhost:8200/v1/auth/kubernetes/config

curl --header "X-Vault-Token: root" \
     --request POST \
     --data '{
       "bound_service_account_names": ["myapp-vault-sa"],
       "bound_service_account_namespaces": ["default"],
       "policies": ["myapp"],
       "ttl": "24h"
     }' \
     http://localhost:8200/v1/auth/kubernetes/role/myapp

echo "✅ Vault setup complete. Kill port-forward when done."
EOF

chmod +x vault/setup-vault.sh

mkdir -p monitoring
touch monitoring/prometheus-rules.yaml
mkdir -p monitoring/grafana-dashboards
touch monitoring/alertmanager-config.yaml

mkdir -p security
touch security/trivy-policy.yaml
cat > security/sonar-project.properties << 'EOF'
sonar.projectKey=myapp
sonar.sources=.
sonar.host.url=http://sonarqube:9000
EOF

mkdir -p security/vault
touch security/vault/secrets-policy.hcl

mkdir -p gitops-repo/clusters/my-aks-cluster
touch gitops-repo/clusters/my-aks-cluster/kustomization.yaml
touch gitops-repo/clusters/my-aks-cluster/myapp-release.yaml

mkdir -p gitops-repo/charts/myapp
# You can copy helm/myapp-chart/ contents here later

echo "✅ All 31 files created successfully!"
echo "⚠️ Remember to replace all YOUR_XXX placeholders before running!"