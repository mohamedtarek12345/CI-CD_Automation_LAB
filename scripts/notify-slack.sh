#!/bin/bash
MESSAGE="$1"
curl -X POST -H 'Content-type: application/json' --data "{\"text\":\"$MESSAGE\"}" YOUR_SLACK_WEBHOOK_URL
