/** \file buffer.h
 * A simple buffer class.
 *
 * \copyright Copyright (c) 2017 Donovan Baarda <abo@minkirri.apana.org.au>
 *
 * \licence Licensed under the GPLv3 License. See LICENSE file for details. */
#ifndef BUFFER_H
#define BUFFER_H

#include <assert.h>
#include <string.h>

#define BUFFER_SIZE 16384

/** The simple buffer class. */
typedef struct {
    size_t len;                 /**< The amount of data in the buffer */
    unsigned char buf[BUFFER_SIZE];     /**< The buffered data. */
} buffer_t;
/** Initialize an empty buffer instance */
static inline void buffer_init(buffer_t *buffer);
/** Fill len data appended to the end of the buffer. */
static inline void buffer_fill(buffer_t *buffer, size_t len);
/** Toss len data discarded from the front of the buffer. */
static inline void buffer_toss(buffer_t *buffer, size_t len);
/** Get the next write start pointer. */
#define buffer_wpos(buffer) ((buffer)->buf + (buffer)->len)
/** Get the available write length. */
#define buffer_wlen(buffer) (BUFFER_SIZE - (buffer)->len)
/** Get the next read start pointer. */
#define buffer_rpos(buffer) ((buffer)->buf)
/** Get the available read length. */
#define buffer_rlen(buffer) ((buffer)->len)
/** Is the buffer empty? */
#define buffer_empty(buffer) (!(buffer)->len)
/** Is the buffer full? */
#define buffer_full(buffer) ((buffer)->len == BUFFER_SIZE)

static inline void buffer_init(buffer_t *buffer)
{
    buffer->len = 0;
}

static inline void buffer_fill(buffer_t *buffer, size_t len)
{
    assert(len <= buffer_wlen(buffer));

    buffer->len += len;
}

static inline void buffer_toss(buffer_t *buffer, size_t len)
{
    assert(len <= buffer_rlen(buffer));

    buffer->len -= len;
    /* Shuffle any remaining data to start of buffer. */
    if (buffer->len) {
        memmove(buffer->buf, buffer->buf + len, buffer->len);
    }
}

#endif                          /* BUFFER_H */
