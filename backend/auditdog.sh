#!/bin/bash

if [ ! -z "$DEBUG" ]; then
  set -x
fi

# Configuration
API_URL="http://localhost:8000/api/v1/commands/explain"
MAX_RETRIES=5
TIMEOUT=15  # seconds
RETRY_DELAY=1  # seconds between retries

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

# Function to clean up temporary files
cleanup() {
  rm -f "$TEMP_JSON" "$TEMP_RESPONSE"
}

# Set trap to ensure cleanup on script exit
trap cleanup EXIT

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
  printf "Debug: API URL = %s\n" "$API_URL"
  printf "Debug: JSON payload:\n"
  cat "$TEMP_JSON"
fi

# Initialize retry counter
RETRY_COUNT=0
SUCCESS=false

# Retry loop
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
  if [ $RETRY_COUNT -gt 0 ]; then
    printf "Retry attempt %d of %d...\n" $RETRY_COUNT $MAX_RETRIES
    sleep $RETRY_DELAY
    # Increase delay for subsequent retries (exponential backoff)
    RETRY_DELAY=$((RETRY_DELAY * 2))
  fi
  
  # Make the API request
  if [ ! -z "$DEBUG" ]; then
    printf "Calling API...\n"
    curl -v -s -m "$TIMEOUT" -X POST "$API_URL" \
      -H "Content-Type: application/json" \
      -d @"$TEMP_JSON" > "$TEMP_RESPONSE" 2>&1
    CURL_STATUS=$?
    printf "Curl status: %d\n" $CURL_STATUS
  else
    curl -s -m "$TIMEOUT" -X POST "$API_URL" \
      -H "Content-Type: application/json" \
      -d @"$TEMP_JSON" > "$TEMP_RESPONSE" 2>&1
    CURL_STATUS=$?
  fi
  
  # Check if curl command succeeded
  if [ $CURL_STATUS -ne 0 ]; then
    printf "🐕 Error: API request failed (curl error %d)\n" $CURL_STATUS
    
    if [ $CURL_STATUS -eq 7 ]; then
      printf "Could not connect to server. Is the API running?\n"
    elif [ $CURL_STATUS -eq 28 ]; then
      printf "Connection timed out. Server might be overloaded.\n"
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    continue  # Try again
  fi
  
  # Check response size
  RESPONSE_SIZE=$(wc -c < "$TEMP_RESPONSE")
  if [ $RESPONSE_SIZE -eq 0 ]; then
    printf "🐕 Error: Received empty response from API\n"
    RETRY_COUNT=$((RETRY_COUNT + 1))
    continue  # Try again
  fi
  
  # Check if the response is valid JSON
  if ! jq . "$TEMP_RESPONSE" > /dev/null 2>&1; then
    printf "🐕 Error: Invalid JSON response\n"
    if [ ! -z "$DEBUG" ]; then
      printf "Response content:\n"
      cat "$TEMP_RESPONSE"
    fi
    RETRY_COUNT=$((RETRY_COUNT + 1))
    continue  # Try again
  fi
  
  # Check for API error response
  if jq -e 'has("detail")' "$TEMP_RESPONSE" > /dev/null 2>&1; then
    ERROR_MSG=$(jq -r '.detail' "$TEMP_RESPONSE")
    printf "🐕 Error from API: %s\n" "$ERROR_MSG"
    RETRY_COUNT=$((RETRY_COUNT + 1))
    continue  # Try again
  fi
  
  # Check if we have all required fields
  if ! jq -e 'has("command") and has("summary") and has("sections") and has("risk_level")' "$TEMP_RESPONSE" > /dev/null 2>&1; then
    printf "🐕 Error: Incomplete response missing required fields\n"
    RETRY_COUNT=$((RETRY_COUNT + 1))
    continue  # Try again
  fi
  
  # If we got here, the API call was successful
  SUCCESS=true
  break
done

# Check if we succeeded after retries
if [ "$SUCCESS" = false ]; then
  printf "🐕 Error: Failed to get command explanation after %d attempts\n" $MAX_RETRIES
  printf "Would you like to execute the command anyway? [y/N] "
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
printf "\n🐕 \033[1mAUDITDOG COMMAND EXPLANATION\033[0m\n"
printf "Command: \033[1m%s\033[0m\n" "$COMMAND"
printf "\n\033[1mSummary:\033[0m %s\n" "$SUMMARY"

# Display risk level with appropriate color
case "$RISK_LEVEL" in
  "critical")
    printf "\n\033[1;37;41mRISK LEVEL: CRITICAL\033[0m\n"
    ;;
  "high")
    printf "\n\033[1;31mRISK LEVEL: HIGH\033[0m\n"
    ;;
  "medium")
    printf "\n\033[1;33mRISK LEVEL: MEDIUM\033[0m\n"
    ;;
  "low")
    printf "\n\033[1;32mRISK LEVEL: LOW\033[0m\n"
    ;;
  "minimal")
    printf "\n\033[1;36mRISK LEVEL: MINIMAL\033[0m\n"
    ;;
  *)
    printf "\n\033[1;34mRISK LEVEL: UNKNOWN\033[0m\n"
    ;;
esac

# Display sections
SECTIONS_COUNT=$(jq '.sections | length' "$TEMP_RESPONSE")
for i in $(seq 0 $((SECTIONS_COUNT-1))); do
  TITLE=$(jq -r ".sections[$i].title" "$TEMP_RESPONSE")
  CONTENT=$(jq -r ".sections[$i].content" "$TEMP_RESPONSE")
  printf "\n\033[1m%s:\033[0m\n%s\n" "$TITLE" "$CONTENT"
done

# Ask for confirmation
printf "\nWould you like to execute this command? [Y/n] "
read -r CONFIRM

# Execute if confirmed (default is yes)
if [[ ! "$CONFIRM" =~ ^[nN]$ ]]; then
  printf "\nExecuting command...\n\n"
  eval "$COMMAND"
fi

# Exit with success
exit 0