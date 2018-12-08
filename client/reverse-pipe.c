#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CHECK(cond, message) if (cond) { perror(message); exit(1); }
#define BADARG(cond) if (cond) return badarg();

static int badarg() {
	fputs("reverse-pipe ... FDIN.FDOUT@PID\n", stderr);
	return 1;
}

static int open_pidfd(const char *pid, const char *fdstr, int flags) {
	char proc_path[1024];
	snprintf(proc_path, sizeof proc_path,
	         "/proc/%s/fd/%s", pid, fdstr);
	int fd = open(proc_path, flags);
	CHECK(fd < 0, proc_path);
	return fd;
}

static void set_nonblock(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);
	if (fl != -1 && !(fl & O_NONBLOCK))
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

struct buffer {
	int in_fd, out_fd;
	fd_set *read_fds;
	fd_set *write_fds;
	unsigned lo, hi;
	char buf[16384];
};

static int has_data(struct buffer *buf) {
	return buf->out_fd >= 0 && buf->lo < buf->hi;
}

static void close_fd(int *fd) {
	if (*fd != -1)
		close(*fd);
	*fd = -1;
}

static void prepare_fds(struct buffer *buf) {
	if (buf->out_fd < 0)
		return;
	if (buf->in_fd >= 0 && buf->hi < sizeof buf->buf)
		FD_SET(buf->in_fd, buf->read_fds);
	if (buf->lo < buf->hi)
		FD_SET(buf->out_fd, buf->write_fds);
}

static void buf_io(struct buffer *buf) {
	if (buf->out_fd >= 0
	    && FD_ISSET(buf->out_fd, buf->write_fds)
	    && buf->lo < buf->hi) {
		int n = write(buf->out_fd, buf->buf + buf->lo,
		              buf->hi - buf->lo);
		if (n > 0) {
			if ((buf->lo += n) >= buf->hi) {
				buf->lo = buf->hi = 0;
				if (buf->in_fd < 0)
					close_fd(&buf->out_fd);
			}
		} else if (errno != EINTR) {
			perror("reverse-pipe write");
			close_fd(&buf->out_fd);
			close_fd(&buf->in_fd);
		}
	}

	if (buf->in_fd >= 0
	    && FD_ISSET(buf->in_fd, buf->read_fds)
	    && buf->hi < sizeof buf->buf) {
		int n = read(buf->in_fd, buf->buf + buf->hi,
		             sizeof buf->buf - buf->hi);
		if (n > 0) {
			buf->hi += n;
			// move buffer, if low space
			if (buf->hi >= sizeof buf->buf - 512
			    && buf->lo >= sizeof buf->buf / 2) {
				n = buf->hi - buf->lo;
				// no overlapping due half buffer empty
				memcpy(buf->buf, buf->buf + buf->lo, n);
				buf->lo = 0;
				buf->hi = n;
			}
		} else if (n == 0 || errno != EINTR) {
			if (n)
				perror("reverse-pipe read");
			close_fd(&buf->in_fd);
			if (buf->lo >= buf->hi)
				close_fd(&buf->out_fd);
		}
	}
}

static void copy_streams(int in, int out) {
	fd_set read_fds, write_fds;
	int nfds = (in > out ? in : out) + 1;
	struct buffer stdin_to_ext = { .in_fd = 0, .out_fd = out,
		.read_fds = &read_fds, .write_fds = &write_fds };
	struct buffer ext_to_stdout = { .in_fd = in, .out_fd = 1,
		.read_fds = &read_fds, .write_fds = &write_fds };

	set_nonblock(0);
	set_nonblock(1);
	while ((stdin_to_ext.out_fd >= 0 && ext_to_stdout.out_fd >= 0)
	       || has_data(&stdin_to_ext) || has_data(&ext_to_stdout)) {
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		prepare_fds(&stdin_to_ext);
		prepare_fds(&ext_to_stdout);
		int result = select(nfds, &read_fds, &write_fds, NULL, NULL);
		if (result < 0 && errno == EINTR)
			continue;
		CHECK(result <= 0, "reverse-pipe select");
		buf_io(&stdin_to_ext);
		buf_io(&ext_to_stdout);
	}
	exit(0); // all ok
}

int main(int argc, char **argv) {
	int arg = 1;
	while (arg < argc && argv[arg][0] == '-')
		++arg;
	BADARG(arg >= argc);

	char *fdin = argv[arg];
	char *pid = strchr(fdin, '@');
	BADARG(!pid);
	*(pid++) = 0;
	char *fdout = strchr(fdin, '.');
	BADARG(!fdout);
	*(fdout++) = 0;

	copy_streams(open_pidfd(pid, fdin, O_RDONLY | O_NONBLOCK),
	             open_pidfd(pid, fdout, O_WRONLY | O_NONBLOCK));
	return 0;
}
