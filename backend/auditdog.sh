COMMAND="$@"

# Extract the actual command and arguments (stripping 'auditdog')
COMMAND_PARTS=($COMMAND)
CMD=${COMMAND_PARTS[0]}
ARGS="${COMMAND#$CMD}"

# Get current username and working directory
USERNAME=$(whoami)
WORKING_DIR=$(pwd)

# API endpoint URL
API_URL="http://localhost:8000/api/v1/commands/explain"

# Prepare the JSON payload
JSON_PAYLOAD=$(cat << EOF
{
  "command": "$CMD",
  "arguments": "$ARGS",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "username": "$USERNAME",
  "working_directory": "$WORKING_DIR"
}
EOF
)

# Make the API request
RESPONSE=$(curl -s -X POST "$API_URL" \
  -H "Content-Type: application/json" \
  -d "$JSON_PAYLOAD")

# Check if the request failed
if [ $? -ne 0 ] || [[ "$RESPONSE" == *"error"* ]]; then
  echo "🐕 Error: Failed to get command explanation"
  echo "Would you like to execute the command anyway? [y/N]"
  read -r CONFIRM
  if [[ "$CONFIRM" == "y" || "$CONFIRM" == "Y" ]]; then
    eval "$COMMAND"
  fi
  exit 1
fi

# Parse and display the command explanation
SUMMARY=$(echo "$RESPONSE" | jq -r '.summary')
RISK_LEVEL=$(echo "$RESPONSE" | jq -r '.risk_level')

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
echo "$RESPONSE" | jq -r '.sections[] | "\n\033[1m\(.title):\033[0m\n\(.content)"'

# Ask for confirmation
echo -e "\nWould you like to execute this command? [Y/n]"
read -r CONFIRM

# Execute if confirmed (default is yes)
if [[ ! "$CONFIRM" =~ ^[nN]$ ]]; then
  echo -e "\nExecuting command...\n"
  eval "$COMMAND"
fi