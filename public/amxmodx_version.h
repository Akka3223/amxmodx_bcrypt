#ifndef _INCLUDE_AMXX_VERSION_INFORMATION_H_
#define _INCLUDE_AMXX_VERSION_INFORMATION_H_

/**
 * @file Contains AMX Mod X version information.
 * @brief This file will redirect to an autogenerated version if being compiled via
 * the build scripts.
 */

#if defined AMXX_GENERATED_BUILD
	#if defined RC_COMPILE
		#undef AMXX_USE_VERSIONLIB
	#endif
	#if defined AMXX_USE_VERSIONLIB
		#include <versionlib.h>
	#else 
		#include <amxmodx_version_auto.h>
	#endif
#else
	#define AMXX_BUILD_TAG        "manual"
	#define AMXX_BUILD_LOCAL_REV  "0"
	#define AMXX_BUILD_CSET       "0"
	#define AMXX_BUILD_MAJOR      "1"
	#define AMXX_BUILD_MINOR      "10"
	#define AMXX_BUILD_RELEASE    "0"

	#define AMXX_BUILD_UNIQUEID AMXX_BUILD_LOCAL_REV ":" AMXX_BUILD_CSET

	#define AMXX_VERSION_STRING   AMXX_BUILD_MAJOR "." AMXX_BUILD_MINOR "." AMXX_BUILD_RELEASE "-" AMXX_BUILD_TAG
	#define AMXX_VERSION_FILE     1,10,0,0
#endif

#define AMXX_BUILD_TIMESTAMP  __DATE__ " " __TIME__

#if !defined(AMXX_GENERATED_BUILD) || !defined(AMXX_USE_VERSIONLIB)
	#define AMXX_VERSION      AMXX_VERSION_STRING
	#define AMXX_BUILD_ID     AMXX_BUILD_UNIQUEID
	#define AMXX_BUILD_TIME   AMXX_BUILD_TIMESTAMP
#endif

#endif /* _INCLUDE_AMXX_VERSION_INFORMATION_H_ */

