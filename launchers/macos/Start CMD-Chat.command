#!/bin/bash
cd "$(dirname "$0")"
if [ -x "CMD-Chat" ]; then
  exec ./CMD-Chat
else
  echo "CMD-Chat was not found."
  echo "Make sure you extracted the complete CMD-Chat release ZIP."
  read -r -p "Press Enter to close..."
fi
