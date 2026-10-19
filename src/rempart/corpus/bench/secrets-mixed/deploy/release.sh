#!/bin/sh
set -eu
# rempart-expect: SEC-GITHUB-TOKEN
export GITHUB_TOKEN={{FAKE_GH_TOKEN}}
# rempart-safe: SEC-GITHUB-TOKEN
export GH_TOKEN="${GH_TOKEN:?missing}"
# rempart-expect: SEC-SLACK-TOKEN
curl -s -H "Authorization: Bearer {{FAKE_SLACK_BOT}}" https://slack.com/api/chat.postMessage -d text=released
