import argparse
import os
from typing import List, Dict
import binascii
import json


def parse_log(path: str) -> List[Dict]:
    f = open(path, 'r')
    options = dict()
    results: List[Dict] = list()
    line = f.readline().strip()
    field, separator = line.split(' ')
    separator = binascii.unhexlify(separator.strip('\\x')).decode('utf-8')
    line = f.readline().strip()
    while line:
        if line.startswith('#'):
            line = line.lstrip('#')
            # print(line)
            # sep = " " if 'separator' not in options else options['separator']
            # print(separator)
            field, value = line.split(separator, 1)
            if field.lower() == 'fields':
                value = value.split(separator)
                options[field] = value
        else:
            results.append(dict(zip(options['fields'], line.split(separator))))
        line = f.readline().strip()
    return results


parser = argparse.ArgumentParser(description="Parsing Zeek native logs into Json")
parser.add_argument("--file", help="File of zeek logs", required=True)
parser.add_argument("--output", help="Json file to output to", required=True)
parser.add_argument("--all", type=bool, help="Parse all file(s) into one output, used to append data to output",
                    default=True, required=False)
args = parser.parse_args()

new_data = parse_log(path=args.file)
if args.all and os.path.exists(args.output):
    old_data = json.load(open(args.output, 'r'))
    new_data += old_data
json.dump(new_data, open(args.output, 'w'))
