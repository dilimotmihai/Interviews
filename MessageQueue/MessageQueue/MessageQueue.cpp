#include "pch.h"
#include <iostream>
#include <list>
#include <cstddef>
#include <thread>


using namespace std;

class Object {

};

class Message {
public:
	int what;
	int arg1;
	int arg2;
	void* obj_c; // C++
	Object* obj_j; // Java

	Message(int what, int arg1, int arg2, void* c, Object* j) {
		this->what = what, this->arg1 = arg1, this->arg2 = arg2,
			this->obj_c = c, this->obj_j = j;
	}
};

class MessageQueue {
private:
	list<Message> messqueue;

public:
	Message* dequeue() {
		if (messqueue.size()) {
			Message& first = messqueue.front();
			printf("dequeue: %d\n", first.what);
			Message* ret = new Message(first);
			messqueue.pop_front();
			return ret;
		}
		return nullptr;
	}

	int enqueue(Message obj) {
		if (messqueue.size() < messqueue.max_size()) {
			printf("enqueue: %d\n", obj.what);
			messqueue.push_back(obj);
			return 1;
		}
		return 0;
	}

	void cleanup_what(int remove_what) {
		messqueue.remove_if([remove_what](Message obj) {return obj.what == remove_what; });
	}
};

void producer(MessageQueue* obj)
{
	while (1) {
		obj->enqueue(Message(9, 9, 9, nullptr, nullptr));
		this_thread::sleep_for(chrono::milliseconds(2000));
	}
}

void consumer(MessageQueue* obj) 
{
	while (1) {
		free(obj->dequeue());
		this_thread::sleep_for(chrono::milliseconds(1000));
	}
}

int main()
{
	MessageQueue mq;
	Message m1 = Message(1, 2, 3, nullptr, nullptr),
		m2 = Message(4, 5, 6, nullptr, nullptr),
		*m3;

	mq.enqueue(m2); mq.enqueue(m1);
	mq.cleanup_what(4);
	m3 = mq.dequeue();

	if (m3)
		printf("It should be m1: %d\n\n", m3->what);

	thread prod1(producer, &mq);
	thread prod2(producer, &mq);
	thread cons(consumer, &mq);

	prod1.join();
	prod2.join();
	cons.join();
	
	return 0;
}