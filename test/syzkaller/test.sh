#!/bin/bash


for dir in test/syzkaller/*/; do
  echo '# Convert Syzkaller API result to delta'
  diff <(python3 fuzzer/syzkaller/api_to_delta.py ${dir}0-api.json | jq .) <(cat ${dir}1-delta.json | jq .)
  echo STEP1: $?
  echo '# Convert delta to pre-processed (reserved CVEs) first run'
  diff <(python3 fuzzer/syzkaller/delta_to_processed.py ${dir}1-delta.json <(echo []) ${dir}0-reserved-cves.json | jq .) <(cat ${dir}2-processed.json | jq .)
  echo STEP2.1: $?
  echo '# Convert delta to pre-processed (reserved CVEs) second run'
  diff <(python3 fuzzer/syzkaller/delta_to_processed.py ${dir}1-delta.json ${dir}2-processed.json ${dir}0-reserved-cves.json | jq .) <(cat ${dir}2-processed.json | jq .)
  echo STEP2.2: $?
  echo '# Convert processed CVEs to actual CVEs'
  diff <(python3 fuzzer/syzkaller/processed_to_cve.py ${dir}2-processed.json | jq .) <(cat ${dir}3-cve.json | jq .)
  echo STEP3: $?
done
