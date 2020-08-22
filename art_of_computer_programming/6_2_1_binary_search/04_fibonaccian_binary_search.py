import argparse
import datetime

def generate_sorted_input(size):
    return list(range(size))

def parse_args():
    parser = argparse.ArgumentParser(description='Search if a specified number is within a sorted list')
    parser.add_argument('size', type=int, help='size of the sorted list')
    parser.add_argument('number', type=int, help='number to look for in the list')
    parser.add_argument('time', type=int, help='how many time we do the search to see differences')

    args = parser.parse_args()
    return args.size, args.number, args.time

init = None
def search(number, sorted_list):
    n = len(sorted_list)

    global init
    if not init:
        p = 0
        q = 1
        i = p + q
        m = -1
        while m < 0:
            p, q = p+q, p
            i = p + q
            m = i - n
        i, p, q = p, q, p - q
        init = i, p ,q, m
    else:
        i, p, q, m = init

    if number > sorted_list[i]:
        i -= m
        i += q
        p = p - q
        q = q - p
    
    while True:
        if number < sorted_list[i]:
            if q == 0:
                return False, -1
            i -= q
            p, q = q, p - q
        elif number > sorted_list[i]:
            if p == 1:
                return False, -1
            i += q
            p = p - q
            q = q - p
        else:
            return True, i

def main():
    size, number,time = parse_args()
    sorted_list = generate_sorted_input(size)
    
    import profile
    start = datetime.datetime.now()
    for i in range(time):
         is_found, index = search(number, sorted_list)
    end = datetime.datetime.now()
    elapsed = end - start
    print(f'Elapsed time: {elapsed}')

    if is_found and number != index:
        raise ValueError(f'Algo seems to be broken, index: {index}')
    if not is_found and 0 <= number < size:
        raise ValueError(f'Algo seems to be broken, {number} should be found')

main()
