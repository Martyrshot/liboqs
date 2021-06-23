#!/usr/bin/env python3

# SPDX-License-Identifier: MIT

import argparse
import copy
import glob
import jinja2
import os
import shutil
import subprocess
import yaml
from pathlib import Path
import sys
import json

parser = argparse.ArgumentParser()
parser.add_argument("--liboqs-root", default=".")
parser.add_argument("--pqclean-dir", default="../PQClean")
args = parser.parse_args()

def load_yaml(filename, encoding='utf-8'):
    with open(filename, mode='r', encoding=encoding) as fh:
        return yaml.safe_load(fh.read())

def store_yaml(filename, contents, encoding='utf-8'):
    with open(filename, mode='w', encoding=encoding) as fh:
        yaml.dump(contents, fh, sort_keys=False, allow_unicode=True)

instructions = load_yaml(
    os.path.join(args.liboqs_root, 'scripts', 'copy_from_upstream', 'copy_from_upstream.yml'),
    encoding='utf-8')

for kem in instructions['kems']:
    if kem['upstream_location'] == 'pqclean':
        kem_doc_yaml_path = os.path.join(args.liboqs_root, 'docs', 'algorithms', 'kem', '{}.yml'.format(kem['name']))
        if os.path.isfile(kem_doc_yaml_path):
            kem_doc_yaml = load_yaml(kem_doc_yaml_path)
        else:
            continue

        for index, scheme in enumerate(kem['schemes']):
            scheme_meta_path = instructions['upstreams'][0]['kem_meta_path'].format_map(scheme)
            scheme_meta_yaml = load_yaml(os.path.join(args.pqclean_dir, scheme_meta_path))

            # Update kem_doc_yaml
            kem_doc_yaml['type'] = scheme_meta_yaml['type']
            kem_doc_yaml['principal-submitters'] = scheme_meta_yaml['principal-submitters']
            if 'auxiliary-submitters' in scheme_meta_yaml:
                kem_doc_yaml['auxiliary-submitters'] = scheme_meta_yaml['auxiliary-submitters']

            kem_doc_scheme = kem_doc_yaml['parameter-sets'][index]
            kem_doc_scheme['name'] = scheme['pretty_name_full']
            kem_doc_scheme['claimed-nist-level'] = scheme_meta_yaml['claimed-nist-level']
            kem_doc_scheme['claimed-security'] = scheme_meta_yaml['claimed-security']
            kem_doc_scheme['length-public-key'] = scheme_meta_yaml['length-public-key']
            kem_doc_scheme['length-ciphertext'] = scheme_meta_yaml['length-ciphertext']
            kem_doc_scheme['length-secret-key'] = scheme_meta_yaml['length-secret-key']
            kem_doc_scheme['length-shared-secret'] = scheme_meta_yaml['length-shared-secret']

            kem_doc_yaml['parameter-sets'][index] = kem_doc_scheme

        store_yaml(kem_doc_yaml_path, kem_doc_yaml)
