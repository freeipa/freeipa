#!/bin/bash
f=$(jq -r '.tool_input.file_path // .tool_response.filePath')
if echo "$f" | grep -q '\.py$'; then
    awk 'length > 79 {found=1; printf "LINE TOO LONG L%d (%d chars): %s\n", NR, length, $0} END {if(found) exit 1}' "$f"
fi
