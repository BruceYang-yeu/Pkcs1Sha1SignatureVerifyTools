#ifndef __OSDEP_FILE__
#define __OSDEP_FILE__

#undef PUBLIC
#undef PUBLIC_DATA
#undef PRIVATE

#if ME_WIN_LIKE
    /*
        Use PUBLIC on function declarations and definitions (*.c and *.h). 
     */
    #define PUBLIC      __declspec(dllexport)
    #define PUBLIC_DATA __declspec(dllexport)
    #define PRIVATE     static
#else
    #define PUBLIC
    #define PUBLIC_DATA extern
    #define PRIVATE     static
#endif

#ifndef ME_TITLE
     #define ME_TITLE "version 1.0.0"
#endif
#ifndef ME_NAME
     #define ME_NAME "sigtool option"
#endif

#ifndef MAXINT
#if INT_MAX
    #define MAXINT      INT_MAX
#else
    #define MAXINT      0x7fffffff
#endif
#endif

#ifndef max
    #define max(a,b)  (((a) > (b)) ? (a) : (b))
#endif
#ifndef min
    #define min(a,b)  (((a) < (b)) ? (a) : (b))
#endif

#ifndef PRO_START_PRINT
	#define PRO_START_PRINT	fprintf(stdout, "\033[1;31;40mProgram Start...\033[0m\n" );
#endif
#ifndef PRO_END_PRINT	
	#define PRO_END_PRINT  fprintf(stdout, "\033[1;31;40mProgram End\033[0m\n" );
#endif

//#define DEBUG
#ifndef DEBUG
	#define DEBUG_HELP fprintf(stdout, "\033[1;31;40m[debug]Line: %d Function: %s\n\033[0m", __LINE__, __FUNCTION__);
#else
	#define DEBUG_HELP
#endif

static void usage() ;
static void AddNovelSupertvHeadV3(char *argv);
static void GenerateNewKey(int num, unsigned long e, string PubkeyFile, string PriKeyFile);
static void Signature(char *argv);
static void Verify(char *argv);
static void Encryption(char *file, string PubkeyFile, string PriKeyFile);
static void Decryption(char *file, string PubkeyFile, string PriKeyFile);

#endif /* defined(__OSDEP_FILE__) */
