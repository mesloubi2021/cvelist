#!/bin/bash


for dir in test/syzkaller/*/; do
  diff <(python3 fuzzer/syzkaller/api_to_delta.py ${dir}0-api.json | jq .) <(cat ${dir}1-delta.json | jq .)
  echo STEP1: $?
  diff <(python3 fuzzer/syzkaller/delta_to_processed.py ${dir}1-delta.json | jq .) <(cat ${dir}2-processed.json | jq .)
  echo STEP2: $?
  diff <(python3 fuzzer/syzkaller/processed_to_cve.py ${dir}2-processed.json | jq .) <(cat ${dir}3-cve.json | jq .)
  echo STEP3: $?
done
