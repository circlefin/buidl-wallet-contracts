#!/usr/bin/env python

import os
import json
import time
import random
import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import ec

def _generate_private_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_numbers = private_key.private_numbers().private_value
    public_key = private_key.public_key()
    x = public_key.public_numbers().x
    y = public_key.public_numbers().y
    return (hex(x), hex(y), hex(private_key_numbers))


def _generate(size: int, fixtureName: str):
    results = []
    while len(results) < size:
        x, y, private_key = _generate_private_key()
        result = {}
        result["private_key"] = private_key
        result["x"] = x
        result["y"] = y
        results.append(result)

    dir_name = os.path.dirname(os.path.realpath(__file__))
    obj = {"numOfKeys": len(results), "results": results}

    with open(f"{dir_name}/../fixtures/{fixtureName}", "w") as json_file:
        json_str = json.dumps(obj, indent=4)
        json_file.write(json_str)


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "numOfKeys", help="Number of keys to generate", type=int,)
    parser.add_argument(
        "fixtureName", help="Fixture file name", type=str,)
    return parser.parse_args()


def main(args):
    numOfKeys = args.numOfKeys
    fixtureName = args.fixtureName
    _generate(numOfKeys, fixtureName)

if __name__ == "__main__":
    args = _parse_args()
    main(args)
