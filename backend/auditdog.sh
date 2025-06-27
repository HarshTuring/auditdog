if [ ! -z "$DEBUG" ]; then
  set -x
fi

# Configuration
API_URL="http://localhost:8000/api/v1/commands/explain"
TIMEOUT=15  # seconds

# Get the command to explain (everything after auditdog)
COMMAND="$@"

# Extract the actual command and arguments
COMMAND_PARTS=($COMMAND)
CMD=${COMMAND_PARTS[0]}
ARGS="${COMMAND#$CMD}"
ARGS="${ARGS## }"  # Trim leading space

# Get current username and working directory
USERNAME=$(whoami)
WORKING_DIR=$(pwd)

# Create a temporary file for the JSON payload
TEMP_JSON=$(mktemp)
TEMP_RESPONSE=$(mktemp)

# Prepare the JSON payload
cat > "$TEMP_JSON" << EOF
{
  "command": "$CMD",
  "arguments": "$ARGS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "username": "$USERNAME",
  "working_directory": "$WORKING_DIR"
}
EOF

# Print debug info if enabled
if [ ! -z "$DEBUG" ]; then
  echo "Debug: API URL = $API_URL"
  echo "Debug: JSON payload:"
  cat "$TEMP_JSON"
fi

# Make the API request and save response to a temporary file
if [ ! -z "$DEBUG" ]; then
  curl -v -s -m "$TIMEOUT" -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d @"$TEMP_JSON" > "$TEMP_RESPONSE" 2>&1
  CURL_STATUS=$?
else
  curl -s -m "$TIMEOUT" -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d @"$TEMP_JSON" > "$TEMP_RESPONSE" 2>&1
  CURL_STATUS=$?
fi

# Check if curl command succeeded
if [ $CURL_STATUS -ne 0 ]; then
  echo "🐕 Error: Failed to connect to AuditDog API (curl error $CURL_STATUS)"
  
  if [ $CURL_STATUS -eq 7 ]; then
    echo "Could not connect to server. Is the API running?"
  elif [ $CURL_STATUS -eq 28 ]; then
    echo "Connection timed out. Server might be overloaded or unreachable."
  fi
  
  # Clean up temp files
  rm -f "$TEMP_JSON" "$TEMP_RESPONSE"
  
  echo "Would you like to execute the command anyway? [y/N]"
  read -r CONFIRM
  if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
    eval "$COMMAND"
  fi
  exit 1
fi

# Get response content
RESPONSE=$(cat "$TEMP_RESPONSE")

# Check if the response is valid JSON
if ! jq . "$TEMP_RESPONSE" > /dev/null 2>&1; then
  echo "🐕 Error: Invalid JSON response from API"
  echo "Response: $RESPONSE"
  
  # Clean up temp files
  rm -f "$TEMP_JSON" "$TEMP_RESPONSE"
  
  echo "Would you like to execute the command anyway? [y/N]"
  read -r CONFIRM
  if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
    eval "$COMMAND"
  fi
  exit 1
fi

# Check for API error response
if jq -e 'has("detail")' "$TEMP_RESPONSE" > /dev/null 2>&1; then
  ERROR_MSG=$(jq -r '.detail' "$TEMP_RESPONSE")
  echo "🐕 Error from API: $ERROR_MSG"
  
  # Clean up temp files
  rm -f "$TEMP_JSON" "$TEMP_RESPONSE"
  
  echo "Would you like to execute the command anyway? [y/N]"
  read -r CONFIRM
  if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
    eval "$COMMAND"
  fi
  exit 1
fi

# Parse and display the command explanation
SUMMARY=$(jq -r '.summary' "$TEMP_RESPONSE")
RISK_LEVEL=$(jq -r '.risk_level' "$TEMP_RESPONSE")

# Display header with formatting
echo -e "\n🐕 \033[1mAUDITDOG COMMAND EXPLANATION\033[0m"
echo -e "Command: \033[1m$COMMAND\033[0m"
echo -e "\n\033[1mSummary:\033[0m $SUMMARY"

# Display risk level with appropriate color
case "$RISK_LEVEL" in
  "critical")
    echo -e "\n\033[1;37;41mRISK LEVEL: CRITICAL\033[0m"
    ;;
  "high")
    echo -e "\n\033[1;31mRISK LEVEL: HIGH\033[0m"
    ;;
  "medium")
    echo -e "\n\033[1;33mRISK LEVEL: MEDIUM\033[0m"
    ;;
  "low")
    echo -e "\n\033[1;32mRISK LEVEL: LOW\033[0m"
    ;;
  "minimal")
    echo -e "\n\033[1;36mRISK LEVEL: MINIMAL\033[0m"
    ;;
  *)
    echo -e "\n\033[1;34mRISK LEVEL: UNKNOWN\033[0m"
    ;;
esac

# Display sections
jq -r '.sections[] | "\n\033[1m\(.title):\033[0m\n\(.content)"' "$TEMP_RESPONSE"

# Clean up temp files
rm -f "$TEMP_JSON" "$TEMP_RESPONSE"

# Ask for confirmation
echo -e "\nWould you like to execute this command? [Y/n]"
read -r CONFIRM

# Execute if confirmed (default is yes)
if [[ ! "$CONFIRM" =~ ^[nN]$ ]]; then
  echo -e "\nExecuting command...\n"
  eval "$COMMAND"
fi