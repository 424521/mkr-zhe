#ifndef __ZY_MM_LOG_H__
#define __ZY_MM_LOG_H__
#include <stdio.h>

#if 0
static struct tm * timenow;
static inline void zy_mm_get_localtime()
{
	static time_t now;
	time(&now);
	timenow = localtime(&now);
	return;
}

#define zy_mm_dbg(fmt, args...)																\
do {																							\
	zy_mm_get_localtime();																		\
	printf("[%4d/%02d/%02d %02d:%02d:%02d][%s(%d)]:" fmt,									\
	timenow->tm_year+1900,timenow->tm_mon,timenow->tm_mday,										\
	timenow->tm_hour,timenow->tm_min,timenow->tm_sec,											\
	__FUNCTION__,__LINE__,##args);																\
} while(0)
#endif
#define zy_mm_dbg printf
#define zy_mm_info printf
#define zy_mm_warn printf
#define zy_mm_error printf
#endif