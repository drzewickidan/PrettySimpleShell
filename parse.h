#ifndef _parse_h_
#define _parse_h_

#include <limits.h>

typedef struct {
    char* cmd;
    char** argv;   /* NULL terminated array of strings */
} Task;

typedef struct {
    Task* tasks;         /* ordered list of tasks to pipe */
    int   ntasks;        /* # of tasks in the parse */

    char* infile;        /* filename of 'infile'  */
    char* outfile;       /* filename of 'outfile' */

    int background;      /* run process in background? */
    int invalid_syntax;  /* parse failed */

    char* cmdline       /* user typed command */;
} Parse;

typedef enum { 
    STOPPED,
    TERM,
    BG,
    FG,
} JobStatus;

typedef struct {
    char* name;
    pid_t* pids;
    unsigned int npids;
    pid_t pgid;
    JobStatus status;
} Job;

Parse* parse_cmdline (char* cmdline);
void parse_destroy (Parse** P);
void parse_debug (Parse* P);

#endif /* _parse_h_ */
