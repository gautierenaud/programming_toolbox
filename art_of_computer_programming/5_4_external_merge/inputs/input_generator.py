#!/usr/bin/env python3

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('inputs', type=int, help='Number of input to generate')

args = parser.parse_args()
inputs = args.inputs

import os
import shutil

# create output dir
current_dir = os.path.dirname(os.path.realpath(__file__))

import random

random_inputs = list(map(lambda x : str(x) + '\n', range(inputs)))
random.shuffle(random_inputs)
print(len(random_inputs))

file_path = os.path.join(current_dir, f'{inputs}_inputs.txt')
with open(file_path, 'w') as f:
    f.writelines(random_inputs)
