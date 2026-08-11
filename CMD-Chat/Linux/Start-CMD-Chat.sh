#!/bin/sh
cd "$(dirname "$0")"
if [ -x "CMD-Chat" ]; then
  exec ./CMD-Chat
else
  echo "CMD-Chat was not found."
  echo "Make sure you extracted the complete CMD-Chat release ZIP."
  printf "Press Enter to close..."
  read _
fi
