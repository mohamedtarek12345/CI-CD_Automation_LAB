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

![CI/CD Lab Architecture](images/architecture.png)

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
