#ifndef __LOG_H__
#define __LOG_H__

#include <stdarg.h>
#include <string.h>


//#ifdef __cplusplus
//extern "C" {
//#endif

typedef enum
{
    LOG_FATAL = 1,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
 //   LOG_TRACE
}log_level_t;

// if log_file is NULL or empty, log to std only
int log_init(log_level_t log_level, const char *log_file);
void log_uninit();


void log(int level, const char *prefix, const char *fmt, ...);

#define log_wrap(level, fmt, ...) \
{\
    const char *file_name = __FILE__; \
    char sep[] = "\\/"; \
    for (unsigned int __i=0; __i<sizeof(sep)/sizeof(sep[0])-1; __i++) \
    {\
        const char *file = strrchr(__FILE__, sep[__i]); \
        if (file!=NULL) \
            { file_name = file+1; break;}\
    } \
    char prefix[1024] = {0};\
    snprintf(prefix, sizeof(prefix)-1, "%s:%d,%s", file_name, __LINE__, __FUNCTION__); \
    log(level, prefix, fmt, ##__VA_ARGS__); \
}

#define log_debug(fmt, ...) log_wrap(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...) log_wrap(LOG_INFO, fmt, ##__VA_ARGS__)
#define log_warn(fmt, ...) log_wrap(LOG_WARN, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...) log_wrap(LOG_ERROR, fmt, ##__VA_ARGS__)
#define log_fatal(fmt, ...) log_wrap(LOG_FATAL, fmt, ##__VA_ARGS__)
//#define log_trace(fmt, ...) log_wrap(LOG_TRACE, fmt, ##__VA_ARGS__)


//#ifdef __cplusplus
//}
//#endif

#endif // __LOG_H__
