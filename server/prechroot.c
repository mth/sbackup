#define _GNU_SOURCE
#include <linux/capability.h>
#include <linux/securebits.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <grp.h>
#include <pwd.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int capset(cap_user_header_t hdrp, const cap_user_data_t datap);

struct cap_data {
	struct __user_cap_header_struct hdr;
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3];
};

static struct passwd fake_pw = {
	.pw_passwd = "x",
	.pw_gecos = ",,,",
	.pw_dir = "/",
	.pw_shell = "/bin/false",
};

static int drop_all_caps() {
	int i;

	for (i = 0; i <= CAP_LAST_CAP; ++i)
		if (i != CAP_SETPCAP && prctl(PR_CAPBSET_DROP, i, 0, 0, 0))
			return errno != EPERM;
	return prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS_LOCKED
			| SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED
			| SECBIT_NOROOT | SECBIT_NOROOT_LOCKED
			| SECBIT_NO_CAP_AMBIENT_RAISE
			| SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED, 0, 0, 0)
		|| prctl(PR_CAPBSET_DROP, CAP_SETPCAP, 0, 0, 0);
}

int open64(const char *pathname, int flags, int mode) {
	static int (*opn)(const char*, int, int);
	static int dev_null;
	int fd;

	if (!opn) {
		if (!(opn = dlsym(RTLD_NEXT, "open64"))) {
			errno = ENOSYS;
			return -1;
		}
		if ((dev_null = opn("/dev/null", 2, 0)) < 0)
			perror("/dev/null");
	}
	if (!pathname) {
		errno = EFAULT;
		return -1;
	}
	if (!strcmp("/dev/null", pathname))
		return dup(dev_null);
	return opn(pathname, flags, mode);
}

struct passwd* getpwuid(uid_t uid) {
	static struct passwd* (*getpw)(uid_t);

	if (uid == fake_pw.pw_uid && fake_pw.pw_name)
		return &fake_pw;
	if (!getpw && !(getpw = dlsym(RTLD_NEXT, "getpwuid"))) {
		errno = ENOSYS;
		return NULL;
	}
	return getpw(uid);
}

__attribute__((constructor)) static void setup(void) {
	static struct cap_data caps =
		{ .hdr = { .version = _LINUX_CAPABILITY_VERSION_3 } };
	struct passwd *pw;
	char *param;
	uid_t uid = 0;
	gid_t gid = 0;

	if (getuid()) {
		fputs("prechroot: not a root\n", stderr);
		return;
	}
	open64(NULL, 0, 0);
	param = getenv("PRECHROOT");

	if (param) {
		uid = strtol(param, &param, 0);
		gid = strtol(param, &param, 0);
		while (*param == ' ')
			++param;
	}
	fake_pw.pw_uid = uid ? uid : getuid();
	fake_pw.pw_gid = gid ? gid : getgid();
	fake_pw.pw_name = fake_pw.pw_uid ? "user" : "root";

	if (!param || !*param)
		fputs("No directory in the PRECHROOT environment variable\n", stderr);
	else if (gid && (setgid(gid) || setgroups(0, &gid)))
		perror("setgid");
	else if (chroot(param) || chdir("/"))
		perror(param);
	else if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		perror("no new privileges");
	else if (drop_all_caps())
		perror("drop capabilities");
	else if (uid && setuid(uid))
		perror("setuid");
	else if (capset(&caps.hdr, caps.data))
		perror("capset");
	else {
		unsetenv("PRECHROOT");
		unsetenv("LD_PRELOAD");
		return;
	}
	_exit(1);
}
