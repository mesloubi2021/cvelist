#!/bin/bash

wget https://linux-mirror-db.storage.googleapis.com/mirror.sl3
sqlite3 -init syzkaller.sql -json mirror.sl3
