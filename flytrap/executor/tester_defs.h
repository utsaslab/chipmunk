#ifndef DB8EFD80_9D3E_409C_A5B4_2B546AB1A019
#define DB8EFD80_9D3E_409C_A5B4_2B546AB1A019

#include "event.h"

typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

const int kMaxArgs = 9;

struct cover_t {
	int fd;
	uint32 size;
	char* data;
	char* data_end;
};

struct thread_t {
	int id;
	bool created;
	event_t ready;
	event_t done;
	uint64* copyout_pos;
	uint64 copyout_index;
	bool colliding;
	bool executing;
	int call_index;
	int call_num;
	int num_args;
	intptr_t args[kMaxArgs];
	intptr_t res;
	uint32 reserrno;
	bool fault_injected;
	cover_t cov;
	cover_t mount_cov;
	bool soft_fail_state;
};



#endif /* DB8EFD80_9D3E_409C_A5B4_2B546AB1A019 */
