/* 
 * File:   debug.h
 * Author: root
 *
 * Created on 30 Октябрь 2014 г., 0:47
 */

#ifndef DEBUG_H
#define	DEBUG_H

#ifdef	__cplusplus
extern "C" {
#endif

    
#ifdef DEBUG
    #define DEBUG_TEST  1
    #define DEBUG_ERROR 1
    #include <stdio.h>
#else
    #define DEBUG_TEST 0
    #define DEBUG_ERROR 1
	#include <stdio.h>
#endif
    
#define DEBUG_PRINT(...) \
            do { if (DEBUG_TEST){ fprintf(stderr, ##__VA_ARGS__); fflush(stderr); } } while (0)

#define DEBUG_PRINTERR(...) \
            do { if (DEBUG_ERROR){ fprintf(stderr, ##__VA_ARGS__); fflush(stderr); } } while (0)
    

#ifdef	__cplusplus
}
#endif

#endif	/* DEBUG_H */

