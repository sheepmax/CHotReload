#include "includes/pipecomm.h"
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

void _send_data(int pipe_fd, uint8_t *data, size_t length) {
	if (write(pipe_fd, data, length) == -1) {
		printf("Could not send data: %s\n", strerror(errno));
	}
}

void send_command(int pipe_fd, uint8_t command) {
	_send_data(pipe_fd, &command, 1);
}