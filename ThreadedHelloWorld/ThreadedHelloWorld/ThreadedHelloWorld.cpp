#include "pch.h"
#include <iostream>
#include <thread>
#include <string>
#include <mutex>
#include <condition_variable>

using namespace std;

mutex mut;
condition_variable thread1, thread2;
bool predicate;

void thread_hello()
{
	unique_lock<mutex> lck(mut);

	while (1) {
		thread1.wait(lck, [] { return !predicate; });
		cout << "Hello,";
		predicate = true;
		thread2.notify_one();
	}
}

void thread_world()
{
	unique_lock<mutex> lck(mut);

	while (1) {
		thread2.wait(lck, [] { return predicate; });
		cout << " World!\n";
		predicate = false;
		thread1.notify_one();
	}
}

int main()
{
	thread hello(thread_hello);
	thread world(thread_world);
	thread1.notify_one();

	hello.join();
	world.join();

	return 0;
}