#define USERFS_DISABLED 0
#define USERFS_SPLITFS 1

#if USERFS != USERFS_DISABLED
int init_userspacefs(void);
int shutdown_userspacefs(void);
#endif