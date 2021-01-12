#include <vector>

using namespace std;

template <typename T> class Heap
{
  public:
	void insert(T key)
	{
		heap.push_back(key);
		increaseKey(heap.size() - 1, key);
	}

	T extractMaximum()
	{
		T maxVal = maximum();
		swap(*heap[0], *heap[heap.size() - 1]);
		heap.pop_back();
		heapify(0);
		return maxVal;
	}

  private:
	vector<T> heap;

	int getRightChild(int index)
	{
		if (index >= 1 && (index << 1) + 1 < heap.size())
		{
			return (index << 1) + 1;
		}
		return -1;
	}

	int getLeftChild(int index)
	{
		if (index >= 1 && (index << 1) < heap.size())
		{
			return index << 1;
		}
		return -1;
	}

	int getParent(int index)
	{
		if (index > 1 && index < heap.size())
		{
			return index >> 1;
		}
		return -1;
	}

	void heapify(int index)
	{
		int leftChildIndex = getLeftChild(index);
		int rightChildIndex = getRightChild(index);

		// find largest index
		int largestIndex = index;
		if (leftChildIndex > 0 && leftChildIndex < heap.size())
		{
			if (*heap[leftChildIndex] > *heap[largestIndex])
			{
				largestIndex = leftChildIndex;
			}
		}
		if (rightChildIndex > 0 && rightChildIndex < heap.size())
		{
			if (*heap[rightChildIndex] > *heap[largestIndex])
			{
				largestIndex = rightChildIndex;
			}
		}

		// if the index is changed, then it is not a heap
		if (index != largestIndex)
		{
			swap(heap[index], heap[largestIndex]);
			heapify(largestIndex);
		}
	}

	void buildHeap()
	{
		for (int i = heap.size() >> 1; i >= 1; --i)
		{
			heapify(i);
		}
	}

	T maximum() { return heap[0]; }

	void increaseKey(int index, T key)
	{
		heap[index] = key;
		while (index > 1 && *heap[getParent(index)] < *heap[index])
		{
			swap(*heap[index], *heap[getParent(index)]);
			index = getParent(index);
		}
	}

	void decreaseKey(int index, T key)
	{
		heap[index] = key;
		heapify(index);
	}
};
