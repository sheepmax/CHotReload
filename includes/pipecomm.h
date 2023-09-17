#ifndef PIPECOMM_H
#define PIPECOMM_H

#include <stdint.h>
#include <stddef.h>

// Message types
#define OUTPUT_M           0x01 // Output a message to the injector
#define PATCH_START_M      0x02 // Begin patching, attach thread
#define PATCH_END_M        0x03 // End patching, detach thread
#define ACK_M              0x04 // Acknowledgement that message has been processed
#define SEEK_M             0x05 // Seek nearest instruction outside of specified range, provided as 2 8 bytes numbers after
#define NACK_M             0x06
#define CONTINUE_M         0x07 // Continue attached process, must be proceeded by PATCH_START_M
#define STOP_M             0x08 // Stop attached process
#define WAIT_TRAP_M        0x09 // Wait for a trap to be hit, then ACK
#define WAIT_TRAP_SIGNAL_M 0x0a // Wait for trap, but continue with a given signal
#define ROLLBACK_M         0x0b // Rolls back RIP 1 byte
#define SINGLESTEP_M       0x0c // Steps program 1 instruciton

void _send_data(int pipe_fd, uint8_t *data, size_t length);
void send_command(int pipe_fd, uint8_t command);

// A printf style function, sends OUTPUT_M
#define send_message(pipe_fd, ...) do {      \
	char *temp = format_str(__VA_ARGS__);    \
	send_command(pipe_fd, OUTPUT_M);         \
	size_t len = strlen(temp) + 1;           \
	_send_data(pipe_fd, (uint8_t *)&len, 1); \
	_send_data(pipe_fd, temp, len);          \
	free(temp);                              \
} while (0)

#endif 