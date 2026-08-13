#!/bin/sh
cd "$(dirname "$0")" || exit 1

# The release ZIP names the binary after the platform it was built for, so look
# for each of the names a Linux package can contain rather than one guess.
for candidate in Linux-x64-CMD-Chat Linux-arm64-CMD-Chat CMD-Chat cmd-chat; do
  if [ -x "./$candidate" ]; then
    CMDCHAT="./$candidate"
    break
  fi
done

if [ -z "$CMDCHAT" ]; then
  echo "CMD-Chat was not found."
  echo "Make sure you extracted the complete CMD-Chat release ZIP."
  printf "Press Enter to close..."
  read _
  exit 1
fi

"$CMDCHAT"
status=$?

# Hold the window open if CMD-Chat exited badly, so the reason is still on
# screen instead of disappearing with the terminal.
if [ "$status" -ne 0 ]; then
  echo
  echo "CMD-Chat closed unexpectedly (exit code $status)."
  printf "Press Enter to close..."
  read _
fi
exit "$status"
