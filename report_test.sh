#!/bin/bash
# Requires curl, jq, and yq

network_size="${1}"
target_endpoint="/report"

peer_ids=$(seq 0 $((${network_size} - 1)))
final_endpoints=()

payload="{\"transaction_id\": \"${2}\", \"claim\": \"${3}\"}"

for peer_id in ${peer_ids}; do
    # Use yq from `pip3 install yq`
    peer_host="$(yq -r ".[\"peers\"][\"${peer_id}\"].host" config.yaml)"
    peer_port="$(yq -r ".[\"peers\"][\"${peer_id}\"].port" config.yaml)"
    peer_endpoint="http://${peer_host}:${peer_port}"
    final_endpoint="${peer_endpoint}${target_endpoint}"
    final_endpoints+=(${final_endpoint})
done

for final_endpoint in ${final_endpoints[@]}; do
    echo "Sending to ${final_endpoint}"

    curl -s -o logs/$(printf "%03d.ret" ${peer_id}) -d "${payload}" -H "Content-Type: application/json" -X POST ${final_endpoint} &
done
