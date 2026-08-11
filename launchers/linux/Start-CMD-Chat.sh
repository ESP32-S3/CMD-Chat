#!/bin/sh
cd "$(dirname "$0")"
if [ -x "CMD-Chat" ]; then
  ./CMD-Chat
elif [ -x "../../bin/cmd-chat" ]; then
  "../../bin/cmd-chat"
else
  echo "CMD-Chat was not found."
  echo "If you downloaded the source code, build it first with scripts/install.py."
  printf "Press Enter to close..."
  read _
fi
