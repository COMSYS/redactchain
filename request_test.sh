#!/bin/bash
# Requires curl, jq, and yq

type="${1}"
peer_id="${2}"

# Use yq from `pip3 install yq`
peer_host="$(yq -r ".[\"peers\"][\"${peer_id}\"].host" config.yaml)"
peer_port="$(yq -r ".[\"peers\"][\"${peer_id}\"].port" config.yaml)"
peer_endpoint="http://${peer_host}:${peer_port}"

if [[ "${type}" == "singlecast" ]]; then # Uses $3: receiver ID
    target_endpoint='/test_echo_singlecast'
    payload="{\"receiver_id\": ${3}, \"msg\": \"test_payload\"}"
elif [[ "${type}" == "eachcast" ]]; then
    payload="{\"base_value\": 42}"
    target_endpoint='/test_echo_eachcast'
elif [[ "${type}" == "broadcast" ]]; then
    payload="{\"test_payload\": \"foo\"}"
    target_endpoint='/test_echo_broadcast'
elif [[ "${type}" == "bracha" ]]; then
    payload="{\"test_payload\": \"foo\"}"
    target_endpoint='/test_echo_bracha'
elif [[ "${type}" == "gettx" ]]; then # Uses $3: transaction ID and $4: redaction method
    if [[ "${4}" == "" ]]; then
        method=""
    else
        method=", \"claim\": \"${4}\""
    fi
    payload="{\"transaction_id\": \"${3}\"${method}}"
    target_endpoint="/gettx"
elif [[ "${type}" == "redactcentral" ]]; then # Uses $3: transaction ID and $4: redaction method
    payload="{\"transaction_id\": \"${3}\", \"claim\": \"${4}\"}"
    target_endpoint="/redactcentral"
fi

final_endpoint="${peer_endpoint}${target_endpoint}"

curl -s -d "${payload}" -H "Content-Type: application/json" -X POST ${final_endpoint} | jq '.'
