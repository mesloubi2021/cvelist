#!/bin/bash

wget -N https://linux-mirror-db.storage.googleapis.com/mirror.sl3
sqlite3 -json mirror.sl3 ".read syzkaller.sql" | jq -c '. |map(. | to_entries | map({"key": .key, "value": (.value//""|split(","))}) | from_entries) | .[]'
