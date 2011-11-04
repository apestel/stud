#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <ev.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <assert.h>

#include "stats.h"

static int *mmap_stats = NULL;
static int max_cores;
static 	ev_io stats_write_ev_handler;
static float req_per_sec;

#define SOCK_PATH "/tmp/stud_stats"

static void setnonblocking(int fd) 
{
    int flag = 1;

    assert (ioctl(fd, FIONBIO, &flag) == 0);
}

int total_sessions()
{
	int total;
	int i;
	
	total = 0;
	for (i = 0;  i < max_cores; i++)
	{
		total += mmap_stats[i];
	}
	return total;
}

void reset_sessions_count()
{
	memset(mmap_stats, 0, sizeof(int) * max_cores);	
}

void process_stats()
{
	req_per_sec = 0.0;
	req_per_sec = total_sessions() / 10.0;
	reset_sessions_count();
}

char *show_stats()
{
	char *result;
	
	asprintf(&result, "req per sec: %.2f\n", req_per_sec);

	return result;
}

void inc_nb_sessions(int child_num)
{
	mmap_stats[child_num]++;
}

void dec_nb_sessions(int child_num)
{
	mmap_stats[child_num]--;
}



/* Create the stats UNIX socket */
static int create_stats_socket() 
{
    int s, t, len;
    struct sockaddr_un local;

    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, SOCK_PATH);
    unlink(local.sun_path);
    len = strlen(local.sun_path) + 1 + sizeof(local.sun_family);
    if (bind(s, (struct sockaddr *)&local, len) == -1) {
        perror("bind");
        exit(1);
    }
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
    setnonblocking(s);
    if (listen(s, 5) == -1) {
        perror("listen");
        exit(1);
    }

    return s;
}

static void stats_write(struct ev_loop *loop, ev_io *w, int revents)
{
	(void)revents;
	char *buffer;
	
	buffer = show_stats();
	write(w->fd, buffer, strlen(buffer) + 1);
	ev_io_stop(loop, w);
	close(w->fd);
	free(buffer);
}

/* libev read handler for the bound socket.  Socket is accepted,
 * the proxystate is allocated and initalized, and we're off the races
 * connecting to the backend */
static void handle_stats_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;

    struct sockaddr_storage addr;
    socklen_t sl = sizeof(addr);
    int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
    if (client == -1) {
        switch (errno) {
        case EMFILE:
            perror("{client} accept() failed; too many open files for this process\n");
			exit(-1);
            break;

        case ENFILE:
            perror("{client} accept() failed; too many open files for this system\n");
			exit(-1);
            break;

        default:
            assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
            break;
        }
        return;
    }

    setnonblocking(client);

    /* set up events */
    ev_io_init(&stats_write_ev_handler, stats_write, client, EV_WRITE);
    ev_io_start(loop, &stats_write_ev_handler);
}

void init_stats(int cores)
{
	int fd;
	int result;
	max_cores = cores;
	
	fd = open("/tmp/stud_stats.bin", O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	result = lseek(fd, sizeof(int) * cores - 1, SEEK_SET);
	if (result == -1) 
	{
		close(fd);
		perror("Error calling lseek() to 'stretch' the file");
		exit(EXIT_FAILURE);
    }
	write(fd, "", 1);
	if (MAP_FAILED != (mmap_stats = mmap(NULL, sizeof(int) * cores, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)))
	{
		reset_sessions_count();	
	}
	else
	{
		perror("mmap failed");
		exit(EXIT_FAILURE);
	}	
}

void stats_loop()
{
	static ev_io stats_listener;
	struct ev_loop *loop;
	int listener_socket;
	loop = ev_default_loop(EVFLAG_AUTO);

    ev_timer stats_timer;

	listener_socket = create_stats_socket();
    ev_timer_init(&stats_timer, process_stats, 10.0, 10.0);
    ev_timer_start(loop, &stats_timer);
    ev_io_init(&stats_listener, handle_stats_accept, listener_socket, EV_READ);
    ev_io_start(loop, &stats_listener);
    ev_loop(loop, 0);
}