#!/usr/bin/env python3

import random

input_size = 100000000

input_list = list(range(input_size))
# random.shuffle(input_list)

for i in reversed(input_list):
    print(i)