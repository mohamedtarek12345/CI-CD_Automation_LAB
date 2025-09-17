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
