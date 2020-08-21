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
    for i in range(len(sorted_list)):
        if number == sorted_list[i]:
            return True, i

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
