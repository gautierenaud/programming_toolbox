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

def search(number, sorted_list):
    lower = 0
    upper = len(sorted_list) - 1

    while not upper < lower:
        mid = (lower + upper) // 2
        if number < sorted_list[mid]:
            upper = mid - 1
        elif number > sorted_list[mid]:
            lower = mid + 1
        else:
            return True, mid

    return False, -1

def main():
    size, number,time = parse_args()
    sorted_list = generate_sorted_input(size)
    
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
