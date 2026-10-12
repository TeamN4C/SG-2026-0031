// SPDX-License-Identifier: GPL-2.0
// Allocate one Binder device in an existing, isolated binderfs mount.
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binderfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct binderfs_device device = {0};
	char control[4096];
	const char *mountpoint;
	const char *name;
	int fd;

	if (argc != 3) {
		fprintf(stderr, "usage: %s MOUNTPOINT DEVICE_NAME\n", argv[0]);
		return 2;
	}
	mountpoint = argv[1];
	name = argv[2];
	if (!*name || strlen(name) > BINDERFS_MAX_NAME ||
	    strchr(name, '/') || !strcmp(name, ".") || !strcmp(name, "..")) {
		fprintf(stderr, "invalid Binder device name\n");
		return 2;
	}
	if (snprintf(control, sizeof(control), "%s/binder-control", mountpoint) >=
	    (int)sizeof(control)) {
		fprintf(stderr, "binderfs path too long\n");
		return 2;
	}
	memcpy(device.name, name, strlen(name) + 1);
	fd = open(control, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open binder-control");
		return 1;
	}
	if (ioctl(fd, BINDER_CTL_ADD, &device) < 0) {
		perror("BINDER_CTL_ADD");
		close(fd);
		return 1;
	}
	close(fd);
	printf("%s/%s major=%u minor=%u\n", mountpoint, device.name,
	       device.major, device.minor);
	return 0;
}
