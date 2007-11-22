/*
 *  Authors:
 *  Karl MacMillan <kmacmill@redhat.com>
 *
 *  Copyright (C) 2007 Red Hat, Inc.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define _GNU_SOURCE /* for asprintf */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define KADMIN_PATH "/usr/kerberos/sbin/kadmin.local"

struct options
{
	char *princ_name;
	char *realm;
	int kstdin, kstdout, kstderr;
};

void *xmalloc(size_t size)
{
	void *foo = malloc(size);
	if (!foo) {
		fprintf(stderr, "malloc error of size %jd\n", size);
		exit(1);
	}
	memset(foo, 0, size);
	
	return foo;
}

void usage(void)
{
	printf("ipa-keytab-util princ-name realm-name\n");
}

struct options *process_args(int argc, char **argv)
{
	struct options* opts;

	opts = xmalloc(sizeof(struct options));

	if (argc != 3) {
		usage();
		exit(1);
	}

	opts->princ_name = argv[1];
	opts->realm = argv[2];
	
	return opts;
}

void drop_caps(void)
{
	cap_t caps;
	int ret;

	if (geteuid() != 0)
		return;
	if (getuid() != 0)
		return;

	caps = cap_init();
	if (!caps) {
		perror("error initializing caps");
		exit(1);
	}
	ret = cap_clear(caps);
	if (ret != 0) {
		perror("could not clear capps");
		exit(1);
	}

	ret = cap_set_proc(caps);
	if (ret != 0) {
		perror("could not drop caps");
		exit(1);
	}

	cap_free(caps);
}

pid_t exec_kadmin_local(struct options *opts)
{
	int stdin_pipes[2];
	int stdout_pipes[2];
	int stderr_pipes[2];
	int ret;
	pid_t chpid;
	char *princ;

	/* create a pair of pipes for stdin / stdout
	   of the child process.
	*/

	if (pipe(stdin_pipes) == -1) {
		perror("creating stdin");
		exit(1);
	}
	   
	if (pipe(stdout_pipes) == -1) {
		perror("creating stdin");
		exit(1);
	}

	if (pipe(stderr_pipes) == -1) {
		perror("creating stdin");
		exit(1);
	}

	chpid = fork();
	if (chpid == -1) {
		perror("fork");
		exit(1);
	}

	/* CHILD */
	if (chpid == 0) {
		/* stdin */
		close(stdin_pipes[1]);
		dup2(stdin_pipes[0], 0);

		/* stdout */
		close(stdout_pipes[0]);
		dup2(stdout_pipes[1], 1);

		/* stderr */
		close(stderr_pipes[0]);
		dup2(stdout_pipes[1], 2);

		/* now exec kadmin.local */
		
		ret = asprintf(&princ, "admin@%s", opts->realm);
		if (!princ) {
			perror("creating bind princ");
			exit(1);
		}
		ret = execl(KADMIN_PATH, "kadmin.local", "-p", princ, NULL);
		free(princ);
		if (ret == -1) {
			perror("exec");
			exit(1);
		}
	} else {
		close(stdin_pipes[0]);
		close(stdout_pipes[1]);
		close(stderr_pipes[1]);

		opts->kstdin = stdin_pipes[1];
		opts->kstdout = stdout_pipes[0];
		opts->kstderr = stdout_pipes[0];
	}

	return chpid;
}

void write_to_kadmin(struct options *opts, char *buf, int len)
{
	int ret;

	ret = write(opts->kstdin, buf, len);
	if (ret != len) {
		perror("write");
		fprintf(stderr, "write is short %d:%d\n", len, ret);
		exit(1);
	}
	fsync(opts->kstdin);
}

char *get_temp_filename(void)
{
	char *fname;
	/* ok - we have to use mktemp here even w/ the race
	 * because kadmin.local barfs if the file exists. The
	 * risk is pretty low and we will try to protect the files
	 * with selinux.
	 *
	 * TODO: generate these files in a safer place than /tmp
	 */
	fname = strdup("/tmp/ipa-keytab-util-XXXXXX");
	if (!fname) {
		fprintf(stderr, "could not allocate temporary file name");
		exit(1);
	}
	fname = mktemp(fname);

	return fname;
}

char *create_keytab(struct options *opts)
{
	char *buf, *fname;
	int ret;
	
	fname = get_temp_filename();

	ret = asprintf(&buf, "ktadd -k %s %s\n", fname, opts->princ_name);
	if (ret == -1) {
		perror("asprintf");
		exit(1);
	}

	write_to_kadmin(opts, buf, ret);

	free(buf);

	write_to_kadmin(opts, "quit\n", sizeof("quit\n"));

	return fname;
}

void read_keytab(char *fname)
{
	FILE *fd;
	char *data;
	long flen, ret;

	fd = fopen(fname, "r");
	if (!fd) {
		fprintf(stderr, "could not open file %s: ", fname);
		perror(NULL);
		exit(1);
	}

	fseek(fd, 0, SEEK_END);
	flen = ftell(fd);
	rewind(fd);

	data = xmalloc(flen);

	/* TODO: handle short reads */
	ret = fread(data, 1, flen, fd);
	if (ret != flen) {
		fprintf(stderr, "short read");
		exit(1);
	}
	
	fclose(fd);

	/* write to stdout */
	ret = fwrite(data, 1, flen, stdout);
	if (ret != flen) {
		fprintf(stderr, "short write");
		exit(1);
	}
}

void remove_keytab(char *filename)
{
	unlink(filename);
}

/* TODO: add significantly better authorization */
int main(int argc, char **argv)
{
	struct options *opts;
	pid_t chpid;
	int status, ret;
	char *fname;

	opts = process_args(argc, argv);

	/* must really be root */
	setuid(0);

	drop_caps();

	
	chpid = exec_kadmin_local(opts);
	fname = create_keytab(opts);

	ret = waitpid(-1, &status, 0);
	if (WEXITSTATUS(status)) {
		fprintf(stderr, "error creating keytab\n");
		exit(1);
	}

	read_keytab(fname);
	remove_keytab(fname);

	return 0;
}
