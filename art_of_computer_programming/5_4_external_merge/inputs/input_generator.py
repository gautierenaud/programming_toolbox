#!/usr/bin/env python3

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('inputs', type=int, help='Number of input to generate')
parser.add_argument('files', type=int, help='Number of file to split the numbers into')

args = parser.parse_args()
inputs, files = args.inputs, args.files

import os
import shutil

# create output dir
current_dir = os.path.dirname(os.path.realpath(__file__))
dir_path = os.path.join(current_dir, f"{inputs}_inputs_{files}_files")
if os.path.exists(dir_path):
    shutil.rmtree(dir_path)
os.mkdir(dir_path)

import random

random_inputs = list(map(lambda x : str(x) + '\n', range(inputs)))
random.shuffle(random_inputs)
print(len(random_inputs))

done = 0
for i in range(files):
    file_inputs_num = inputs // files
    if i == files - 1:
        file_inputs_num = inputs - done
    print(i, done, file_inputs_num)
    file_path = os.path.join(dir_path, f'{i + 1}_{file_inputs_num}_inputs.txt')
    print(f'file is {file_path}')
    with open(file_path, 'w') as f:
        f.writelines(random_inputs[done:done + file_inputs_num])
        done += file_inputs_num
