/*
 * TF5 IBS - Shared File I/O Utilities for Core PKG Tools
 *
 * Contains common file operations used by tf5_ibs_keygen and tf5_ibs_issue.
 */

#ifndef TF5_IBS_FILE_UTIL_H
#define TF5_IBS_FILE_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/*
 * Write binary data to file with specified permissions
 */
static inline int write_key_file(const char *path, const uint8_t *data, size_t len, mode_t mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        perror("Failed to create output file");
        return -1;
    }

    ssize_t n = write(fd, data, len);
    close(fd);

    if (n != (ssize_t)len) {
        fprintf(stderr, "Failed to write %zu bytes to %s\n", len, path);
        return -1;
    }

    return 0;
}

#endif /* TF5_IBS_FILE_UTIL_H */
