#!/bin/bash
IMAGE="$1"
trivy image --exit-code 1 --severity CRITICAL "$IMAGE"
