#!/bin/bash
echo "🚀 Bootstrapping Flux CD..."

flux bootstrap github \
  --owner=yourname \
  --repository=gitops-repo \
  --branch=main \
  --path=clusters/my-aks-cluster \
  --personal

echo "✅ Flux bootstrapped. Your cluster is now GitOps-managed!"
