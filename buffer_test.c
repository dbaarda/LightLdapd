/* Force DEBUG on so that tests can use assert(). */
#undef NDEBUG
#include <assert.h>
#include "buffer.h"

int main(void)
{
    buffer_t b;

    buffer_init(&b);
    assert(b.len == 0);
    assert(buffer_empty(&b));
    assert(!buffer_full(&b));
    assert(buffer_wpos(&b) == b.buf);
    assert(buffer_wlen(&b) == BUFFER_SIZE);
    assert(buffer_rpos(&b) == b.buf);
    assert(buffer_rlen(&b) == 0);
    for (size_t i = 0; i < 17; i++) {
        buffer_wpos(&b)[i] = (unsigned char)i;
    };
    buffer_fill(&b, 17);
    assert(b.len == 17);
    assert(!buffer_empty(&b));
    assert(!buffer_full(&b));
    assert(buffer_wpos(&b) == b.buf + 17);
    assert(buffer_wlen(&b) == BUFFER_SIZE - 17);
    assert(buffer_rpos(&b) == b.buf);
    assert(buffer_rlen(&b) == 17);
    for (size_t i = 0; i < buffer_rlen(&b); i++) {
        assert(buffer_rpos(&b)[i] == (unsigned char)(i));
    }
    buffer_toss(&b, 5);
    assert(b.len == 12);
    assert(!buffer_empty(&b));
    assert(!buffer_full(&b));
    assert(buffer_wpos(&b) == b.buf + 12);
    assert(buffer_wlen(&b) == BUFFER_SIZE - 12);
    assert(buffer_rpos(&b) == b.buf);
    assert(buffer_rlen(&b) == 12);
    for (size_t i = 0; i < buffer_rlen(&b); i++) {
        assert(buffer_rpos(&b)[i] == (unsigned char)(i + 5));
    }
    buffer_toss(&b, 12);
    assert(b.len == 0);
    assert(buffer_empty(&b));
    assert(!buffer_full(&b));
    assert(buffer_wpos(&b) == b.buf);
    assert(buffer_wlen(&b) == BUFFER_SIZE);
    assert(buffer_rpos(&b) == b.buf);
    assert(buffer_rlen(&b) == 0);
    buffer_fill(&b, BUFFER_SIZE);
    assert(b.len == BUFFER_SIZE);
    assert(!buffer_empty(&b));
    assert(buffer_full(&b));
    assert(buffer_wpos(&b) == b.buf + BUFFER_SIZE);
    assert(buffer_wlen(&b) == 0);
    assert(buffer_rpos(&b) == b.buf);
    assert(buffer_rlen(&b) == BUFFER_SIZE);
}
