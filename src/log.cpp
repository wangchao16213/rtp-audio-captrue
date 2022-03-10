#include "log.h"

#include <time.h>
//#include <string>
#include <string.h>
//#include <vector>
#include <assert.h>
#include <stdio.h>


//#include <sys/time.h>
//#include <dirent.h>
//#include <sys/stat.h>
//#include <sys/types.h>
//#include <unistd.h>
//#include <pthread.h>
#include <ortp/port.h>


//define
#define LOG_MAX_SIZE 4096

//variable
static log_level_t g_log_level = LOG_INFO;

static FILE *g_file=NULL;

static bool g_thread_safe = true;
static ortp_thread_t g_mutex;


//function
static bool log_level_enabled(int level);
static const char *log_level_desc(int level);
void localtime3(tm *time, long *usec);

#ifndef gettid
#if	defined(WIN32) || defined(_WIN32)
#include "windows.h"
unsigned long  gettid()
{
	return GetCurrentThreadId();
}
#else
{
#include <unistd.h>
#include <sys/syscall.h>
	pid_t gettid()
	{
		return syscall(SYS_gettid);
	}
}
#endif
#endif

int log_init(log_level_t log_level, const char *log_file)
{
    g_log_level = log_level;

    if (g_thread_safe)
        ortp_mutex_init(&g_mutex, NULL);

	if (log_file!=NULL && strlen(log_file)>0)
	{
		g_file = fopen(log_file, "ab");
		if (g_file == NULL)
		{
			fprintf(stderr, "open log file error, path=%s\n", log_file);
			return -1;
		}
	}


    return 0;
}

void log_uninit()
{
    if (g_thread_safe)
       ortp_mutex_destroy(&g_mutex);

    if (g_file!=NULL)
    {
        fclose(g_file);
        g_file = NULL;
    }
}

static char *get_current_time_str(char *buf)
{
    struct tm time = {0};
    long usec = 0;
    localtime3(&time, &usec);

    if (buf!=NULL)
    sprintf(buf, "%i-%.2i-%.2i %.2i:%.2i:%.2i:%.3i",
                              1900+time.tm_year, 1+time.tm_mon, time.tm_mday, time.tm_hour, time.tm_min, time.tm_sec, (int)(usec/1000));
    return buf;
}

static void _log(int level, const char *prefix, const char *fmt, va_list args)
{
    char msg[LOG_MAX_SIZE] = {0};
    vsnprintf(msg, sizeof(msg)-1, fmt, args);

    const char *desc = log_level_desc(level);

    char time[128] = {0};
    get_current_time_str(time);

    char msg2[LOG_MAX_SIZE+256] = {0};
    if (prefix!=NULL&&prefix[0]!='\0')
        snprintf(msg2, sizeof(msg2)-1, "[%s] [%s] [t%lu] [%s] %s\n", desc, time, gettid(), prefix, msg);
    else
        snprintf(msg2, sizeof(msg2)-1, "[%s] [%s] [t%lu] %s\n", desc, time, gettid(), msg);

    if (g_thread_safe)
       ortp_mutex_lock(&g_mutex);

	fprintf(stderr, "%s", msg2);
	if (g_file!=NULL)
	{
		fwrite(msg2, strlen(msg2), 1, g_file);
		fflush(g_file);
	}

    if (g_thread_safe)
       ortp_mutex_unlock(&g_mutex);
}

void log(int level, const char *prefix, const char *fmt, ...)
{
    if (log_level_enabled(level))
    {
        va_list args;
        va_start(args, fmt);
        _log(level, prefix, fmt, args);
        va_end(args);
    }
}

bool log_level_enabled(int level)
{
    return (level<=g_log_level);
}

const char *log_level_desc(int level)
{
    const char *desc="undef";
    switch (level)
    {
    case LOG_DEBUG:
        desc = "debug";
        break;
    case LOG_INFO:
        desc = "info";
        break;
    case LOG_WARN:
        desc = "warn";
        break;
    case LOG_ERROR:
        desc = "error";
        break;
    case LOG_FATAL:
        desc = "fatal";
        break;
//	case LOG_TRACE:
//		desc = "trace";
//		break;
    default:
        break;
    }

    return desc;
}

void localtime3(tm *time, long *usec)
{
    struct tm *lt;
    struct timeval tp;
    time_t tt;
    gettimeofday(&tp, NULL);
    tt = (time_t)tp.tv_sec;

#ifndef _WIN32
    lt = localtime_r(&tt, time);
#else
    localtime_s(time, &tt);
#endif

    if (usec!=NULL)
        *usec = tp.tv_usec;
}
