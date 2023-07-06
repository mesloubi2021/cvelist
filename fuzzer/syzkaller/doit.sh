#!/bin/bash

function process_osv() {
    ./db_to_list.sh > list.json
    python3 ./list_to_unique.py list.json > unique.json
    python3 ./unique_to_delta.py unique.json > delta.json
    python3 ./delta_to_processed.py $1 delta.json > $2
    python3 ./processed_to_osv.py $2
}

process_osv <(echo []) base.json | jq -c .[]
