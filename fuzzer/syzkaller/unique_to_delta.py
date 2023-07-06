#!/usr/bin/python3

import itertools
import json
import sys

def main(argv):
    bugs = []
    if len(argv) < 1:
        raise Exception("No input file")

    with open(argv[0]) as unique_file:
        unique_bugs = json.load(unique_file)
        for bug in unique_bugs:
            bugs.append({
                "cves": bug["cve"],
                "osvs": [],
                "unique_ids": list(itertools.chain.from_iterable(bug.values())),
                "summary": "",
                "references": [],
                "versions": {
                    "fixed": bug["fixed_by"],
                    "affected": bug["introduced_by"]
                }
            })
    print(json.dumps(bugs))

if __name__ == "__main__":
   main(sys.argv[1:])
