#ifndef A6A1828B_09C2_4501_A64F_884DAA2025B1
#define A6A1828B_09C2_4501_A64F_884DAA2025B1

#include <pthread.h>
#include <time.h>

typedef struct {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	int state;
} event_t;

#endif /* A6A1828B_09C2_4501_A64F_884DAA2025B1 */
