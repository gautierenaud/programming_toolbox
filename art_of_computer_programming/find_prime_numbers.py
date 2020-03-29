"""Implementation of exercise 5.2.3.15"""
from queue import PriorityQueue

# we will look at all the prime below or equal to n
n = int(input())

primes = [2, 3]
prime_num = 2
prime_candidate = 5
dist_next_candidate = 2
# one candidate: (u, v, 6p) with p smallest prime divisor of u, v = 2p or 4p, and u + v not divisible by 3
candidate_queue = PriorityQueue()
candidate_queue.put((25, 10, 30))
queue_num = 1
next_increase_point = 25

while prime_candidate < n:
    q, q1, q2 = candidate_queue.get()
    candidate_queue.put((q + q1, q2 - q1, q2))
    while prime_candidate > q:
        q, q1, q2 = candidate_queue.get()
        candidate_queue.put((q + q1, q2 - q1, q2))

    while prime_candidate < q:
        prime_num += 1
        primes.append(prime_candidate)
        prime_candidate += dist_next_candidate
        dist_next_candidate = 6 - dist_next_candidate

    if prime_candidate > n:
        break

    elif prime_candidate == next_increase_point:
        queue_num += 1
        u = primes[queue_num + 1]
        next_increase_point = u ** 2
        if u % 3 == 2:
            candidate_queue.put((next_increase_point, 2 * u, 6 * u))
        elif u % 3 == 1:
            candidate_queue.put((next_increase_point, 4 * u, 6 * u))

    prime_candidate += dist_next_candidate
    dist_next_candidate = 6 - dist_next_candidate

print(primes)