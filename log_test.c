/* Force DEBUG on so that tests can use assert(). */
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include "log.h"

/* openlog() stub function for testing. */
void openlog(const char *ident, int option, int facility)
{
    printf("log_test: openlog(\"%s\", %#x, %d)\n", ident, option, facility);
}

/* syslog() stub function for testing. */
void syslog(int priority, const char *format, ...)
{
    printf("log_test: syslog(%d, \"%s\", ...)\n", priority, format);
}

/* setlogmask() stub function for testing. */
int setlogmask(int mask)
{
    printf("log_test: setlogmask(%#x)\n", mask);
    return LOG_UPTO(LOG_DEBUG);
}

int main(void)
{
    /* Test default behaviour */
    assert(log_level == LOG_DEBUG);
    assert(log_func == errlog);
    assert(log_prefix == log_prefix_color);
    ldebug("something interesting");
    linfo("something boring");
    lnote("something important");
    lwarn("something concerning");
    lwarnx("something concerning");
    /* Test syslog behavior */
    log_init("test", 1, LOG_WARNING);
    assert(log_level == LOG_WARNING);
    assert(log_func == syslog);
    assert(log_prefix == log_prefix_plain);
    ldebug("something interesting");
    linfo("something boring");
    lnote("something important");
    lwarn("something concerning");
    lwarnx("something concerning");
    /* Test errlog behaviour */
    log_init("test", 0, LOG_ERR);
    assert(log_level == LOG_ERR);
    assert(log_func == errlog);
    assert(log_prefix == log_prefix_color);
    ldebug("something interesting");
    linfo("something boring");
    lnote("something important");
    lwarn("something concerning");
    lwarnx("something concerning");
    lerr(0, "something scary");
    lerrx(1, "lerr() failed to exit");
}
