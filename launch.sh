#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

if [[ -x "bin/cmd-chat" ]]; then
  exec "./bin/cmd-chat"
fi
if [[ -x "cmd-chat" ]]; then
  exec "./cmd-chat"
fi

echo "CMD-Chat executable was not found."
echo "Expected: bin/cmd-chat or cmd-chat"
exit 1
