#!/bin/bash


for dir in test/syzkaller/*/; do
  diff <(python3 fuzzer/syzkaller/syzkaller_to_unique_bug.py ${dir}0-api-response-get-bugs.json | jq .) <(cat ${dir}1-unique-bugs.json | jq .)
  echo STEP1: $?
  diff <(python3 fuzzer/syzkaller/unique_bug_to_cve.py ${dir}1-unique-bugs.json | jq .) <(cat ${dir}2-cves5.json | jq .)
  echo STEP2: $?
done
