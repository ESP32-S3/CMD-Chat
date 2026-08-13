#!/bin/sh
# ChromeOS Linux environment launcher.
# Keep this file beside the CMD-Chat binary and ChromeOS client files.
cd "$(dirname "$0")" || exit 1

for candidate in ChromeOS-x64-CMD-Chat Linux-x64-CMD-Chat CMD-Chat cmd-chat; do
  if [ -x "./$candidate" ]; then
    CMDCHAT="./$candidate"
    break
  fi
done

if [ -n "$CMDCHAT" ]; then
  # The core is always reachable while it runs, so the Python frontend does not
  # have to ask anyone to host first.
  "$CMDCHAT" host &
  CORE_PID=$!
  trap 'kill "$CORE_PID" 2>/dev/null' EXIT
fi

if command -v python3 >/dev/null 2>&1 && [ -f "cmd_chat.py" ]; then
  exec python3 cmd_chat.py
fi

echo "CMD-Chat ChromeOS client could not be started."
echo "Make sure the complete ChromeOS package was extracted and Python 3 is available."
printf "Press Enter to close..."
read _
exit 1
