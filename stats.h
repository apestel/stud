void init_stats(int cores);
void stats_loop();
void inc_nb_sessions(int child_num);
void dec_nb_sessions(int child_num);
static void setnonblocking(int fd);
