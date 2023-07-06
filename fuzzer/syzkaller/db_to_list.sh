#!/bin/bash

wget -N https://linux-mirror-db.storage.googleapis.com/mirror.sl3
wget -N https://linux-mirror-db.storage.googleapis.com/syzkaller.tar.gz

tar xzf syzkaller.tar.gz syzkaller
sqlite3 -json mirror.sl3 ".read db_to_list.sql" | jq -c '. |map(. | to_entries | map({"key": .key, "value": (.value//""|split(","))}) | from_entries) | .[]'
