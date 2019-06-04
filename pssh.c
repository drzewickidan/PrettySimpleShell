#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <readline/readline.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include "builtin.h"
#include "parse.h"

#define N_JOBS 100
#define N_SIG 31
/*******************************************
 * Set to 1 to view the command line parse *
 *******************************************/
#define DEBUG_PARSE 0


int shell_terminal;
pid_t shell_pgid;
Job jobs[N_JOBS] = {{0}};
char *signame[]={"INVALID", "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGPOLL", "SIGPWR", "SIGSYS", NULL};


void print_ferror (int err) {
    if (err == EAGAIN)
        printf("kernel: maximum number of PIDs reached\n");
    else
        printf("kernal: error calling fork(): %s\n", strerror(err));
}


void print_W ()
{
    printf("           .---.\n");
    printf("          /. ./|\n");
    printf("      .--'.  ' ;\n");
    printf("     /__./ \\ : |\n");
    printf(" .--'.  '   \\' .\n");
    printf("/___/ \\ |    ' '\n");
    printf(";   \\  \\;      :\n");
    printf(" \\   ;  `      |\n");
    printf("  .   \\    .\\  ;\n");
    printf("   \\   \\   ' \\ |\n");
    printf("    :   '  |--\" \n");
    printf("     \\   \\ ;    \n");
    printf("      '---\"     \n");
}


void print_banner ()
{
    printf ("                    ________   \n");
    printf ("_________________________  /_  \n");
    printf ("___  __ \\_  ___/_  ___/_  __ \\ \n");
    printf ("__  /_/ /(__  )_(__  )_  / / / \n");
    printf ("_  .___//____/ /____/ /_/ /_/  \n");
    printf ("/_/ Type 'exit' or ctrl+c to quit\n\n");
}


/* returns a string for building the prompt
 *
 * Note:
 *   If you modify this function to return a string on the heap,
 *   be sure to free() it later when appropirate!  */
static char* build_prompt ()
{
    char cwd[PATH_MAX];
    static char prompt[PATH_MAX+2];

    strcpy(prompt, getcwd(cwd, PATH_MAX));
    strcat(prompt, "$ ");
    return prompt; 
}


/* return true if command is found, either:
 *   - a valid fully qualified path was supplied to an existing file
 *   - the executable file was found in the system's PATH
 * false is returned otherwise */
static int command_found (const char* cmd)
{
    char* dir;
    char* tmp;
    char* PATH;
    char* state;
    char probe[PATH_MAX];

    int ret = 0;

    if (access (cmd, X_OK) == 0)
        return 1;

    PATH = strdup (getenv("PATH"));

    for (tmp=PATH; ; tmp=NULL) {
        dir = strtok_r (tmp, ":", &state);
        if (!dir)
            break;

        strncpy (probe, dir, PATH_MAX);
        strncat (probe, "/", PATH_MAX);
        strncat (probe, cmd, PATH_MAX);

        if (access (probe, X_OK) == 0) {
            ret = 1;
            break;
        }
    }

    free (PATH);
    return ret;
}


void put_pgid_in_foreground (pid_t pgid) 
{
    void (*old)(int);

    old = signal (SIGTTOU, SIG_IGN);
    tcsetpgrp (shell_terminal, pgid);
    signal (SIGTTOU, old);
}


void set_job_pgid (pid_t pid, int job_id)
{
    if (!jobs[job_id].pgid) {
        jobs[job_id].pgid = pid;
    }
    setpgid (pid, jobs[job_id].pgid);
}


int get_new_job_id ()
{
    int i;
    
    for (i = 0; i < N_JOBS; i++) {
        if (jobs[i].npids == 0) {
            return i;
        }
    }

    return -1;
}


int insert_job (Job job)
{
    int job_id = get_new_job_id();
    
    if (job_id < 0) return -1;

    jobs[job_id] = job;
    return job_id;
}


int get_job_id_by_pid (pid_t pid, int terminate)
{
    unsigned int i, j;
    for (i = 0; i < N_JOBS; i++) {
        if (jobs[i].npids != 0) {
            for (j = 0; j < jobs[i].npids; j++) {
                if (jobs[i].pids[j] == pid) {
                    if (terminate)
                        jobs[i].pids[j] = 0;
                    return i;
                }
            }
        }
    }
    
    return -1;
}


void set_job_status (int job_id, JobStatus status)
{
    jobs[job_id].status = status;
}


void remove_job (int job_id)
{
    jobs[job_id].npids = 0;
    free(jobs[job_id].name);
    free(jobs[job_id].pids);
}


int is_job_completed (int job_id)
{
    int j;
    for (j = 0; j < jobs[job_id].npids; j++) {
        if (jobs[job_id].pids[j] != 0)
            return 0;
    }

    return 1;
}


void print_job_pids(int job_id)
{
    int j;
    printf("[%d]", job_id);
    for (j = 0; j < jobs[job_id].npids; j++) {
        if (jobs[job_id].pids[j] != 0) {
            printf(" %d", jobs[job_id].pids[j]);
        }
    }
    
    printf("\n");
}


void print_job_status (int job_id)
{
    if (jobs[job_id].npids != 0) {
        if (jobs[job_id].status == FG || jobs[job_id].status == BG)
            printf("[%d] + running       %-s\n", job_id, jobs[job_id].name);
        else if (jobs[job_id].status == TERM)
            printf("[%d] + done          %-s", job_id, jobs[job_id].name);
        else if (jobs[job_id].status == STOPPED)
            printf("[%d] + stopped       %-s\n", job_id, jobs[job_id].name);
    }   
}

void reap_background ()
{
    int j;
    for (j = 0; j < N_JOBS; j++) {
        if (jobs[j].npids != 0) {
            if (jobs[j].status == TERM) {
                print_job_status(j);
                printf("\n");
                fflush(stdout);
                remove_job(j);
            }
        }
    }
}


void handler_sigchld (int sig)
{
    pid_t child;
    int status, job_id;

    while ((child = waitpid (-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {
        if (WIFSTOPPED (status)) {
            job_id = get_job_id_by_pid(child, 0);
            
            if (child == jobs[job_id].pgid) {
                if (jobs[job_id].status != BG) {
                    printf("[%d] + suspended     %-s\n", job_id, jobs[job_id].name);
                }
                
                set_job_status(job_id, STOPPED);
                put_pgid_in_foreground(shell_pgid);
            }
        }
        
        else if (WIFCONTINUED (status)) {
            job_id = get_job_id_by_pid(child, 0);
            
            if (child == jobs[job_id].pgid) {
                if (jobs[job_id].status != FG) {
                    printf("[%d] + continued     %-s\n", job_id, jobs[job_id].name);
                }

                if (tcgetpgrp(shell_terminal) == getpid()) {
                    set_job_status(job_id, BG);
                }
            }
        }

        else {
            /* child is done */
            job_id = get_job_id_by_pid(child, 1);
            
            if (is_job_completed(job_id)) {
                
                if (jobs[job_id].status != BG) {
                    put_pgid_in_foreground(shell_pgid);
                    remove_job(job_id);
                }

                else {
                    set_job_status(job_id, TERM);
                    
                    if (tcgetpgrp(shell_terminal) == getpid()) {
                        printf("\n");
                        print_job_status(job_id);
                        fflush(stdout);
                        remove_job(job_id);
                    }
                }
            }
        }
    }
}


void handler_sigttou (int sig)
{
    /* we got here because we tried to write to stdout while in the
     * background.  let's wait (blocking) for a signal to come in and
     * then check again if we have become the foreground process group.
     * ideally, we will catch a SIGCHLD in here, which will give us the
     * foreground again, which should cause the parent to exit this
     * handler */
    while(tcgetpgrp(shell_terminal) != getpid())
        pause();
    
    reap_background();
}


void redirect (int oldfd, int newfd)
{
	if (oldfd != newfd) {
		dup2(oldfd, newfd);
		close(oldfd);
	}
}


void execute_process (char** argv, int fdin, int fdout) 
{
    redirect(fdin, STDIN_FILENO);
	redirect(fdout, STDOUT_FILENO);
	execvp(argv[0], argv);
}


void builtin_jobs ()
{
    unsigned int job_id;
    
    for(job_id = 0; job_id < N_JOBS; job_id++) {
        if (jobs[job_id].npids != 0) {
            print_job_status(job_id);
        }
    }
}


void builtin_fg (char* arg)
{
    char* endptr;
    int job_id = strtol(arg, &endptr, 0);
    pid_t pgid = jobs[job_id].pgid; 
    
    if (*endptr != '\0') {
        printf("pssh: invalid job number: [%s]\n", arg);
        return;
    }
    
    if (jobs[job_id].status == TERM) {
        printf("pssh: job has terminated: [%d]\n", job_id);
        return;
    }

    set_job_status(job_id, FG);
    
    if (kill(-pgid, SIGCONT) < 0 || pgid < 1) {
        printf("pssh: invalid job number: [%d]\n", job_id);
        return;
    }
   
    put_pgid_in_foreground(jobs[job_id].pgid);
}


void builtin_bg (char* arg)
{
    char* endptr;
    int job_id = strtol(arg, &endptr, 0);
    pid_t pgid = jobs[job_id].pgid;

    if (*endptr != '\0') {
        printf("pssh: invalid job number: [%s]\n", arg);
        return;
    }

    if (jobs[job_id].status == TERM) {
        printf("pssh: job has terminated: [%d]\n", job_id);
        return;
    }
    
    set_job_status(job_id, BG);

    if (kill(-pgid, SIGCONT) < 0 || pgid < 1) {
        printf("pssh: invalid job number: [%d]\n", job_id);
        return;
    }
    
    put_pgid_in_foreground(shell_pgid);
}


void builtin_kill (char** argv, int argc)
{
    
    int pid, sig, job_id;
    unsigned int i = 1;
    
    if (argc == 1) {
        goto kerror;
    }

    if (strcmp(argv[1], "-l") == 0 && argc == 2) {
        for (i=1; i <= N_SIG; i++) {
            if (((i-1) % 5) == 0 && (i-1) != 0)
                printf("\n");
             printf("%2i) %-10s", i, signame[i]);
        }
        printf("\n");
        return;
    }

    /* -s provided */
    if (!strcmp(argv[1], "-s")) {
        if (argv[2] != NULL)
            sig = strtol(argv[2], NULL, 10);
        else
            goto kerror;
        i = 3;
    }

    else {
        sig = SIGTERM;
    }
    
    while (i < argc) {
        if (argv[i][0] == '%') {
            job_id = strtol(argv[i] + 1, NULL, 10);

            if (jobs[job_id].npids != 0) {
                pid = jobs[job_id].pgid * -1;
            }
            
            else {
                printf("pssh: invalid job number: [%d]\n", job_id);
                i++;
                continue;
            }
        }

        else { 
            pid = strtol(argv[i], NULL, 10);
        }

        if (pid == 0)
            return;

        if (kill(pid, sig) == -1) {
            if (argv[i][0] != '%') 
                printf("pssh: invalid pid: [%d]\n", pid);
            else
                printf("pssh: invalid job number: [%d]\n", job_id);
        }
        
        else {
            if (sig == 0) { 
                if (argv[i][0] != '%') 
                    printf("pssh: pid %i exists and is able to receive signals\n", pid);
                else
                    printf("pssh: job number %i exists and is able to receive signals\n", job_id);
            }
        }
        i++;
    }

    return;

kerror:
    printf("Usage: kill [-s signal] <pid> | %c<job> ...\n\nOptions:\n", '%');
    printf("   %-14s Sends <signal> to <pid> | %c<job>\n", "-s <signal>", '%');
    printf("   %-14s Lists all signal numbers with their names\n", "-l");
    
}


void builtin_which (char* exe)
{
    char* dir;
    char* tmp;
    char* PATH;
    char* state;
    char probe[PATH_MAX];

    PATH = strdup (getenv("PATH"));

    for (tmp=PATH; ; tmp=NULL) {
        dir = strtok_r (tmp, ":", &state);
        if (!dir)
            break;

        strncpy (probe, dir, PATH_MAX);
        strncat (probe, "/", PATH_MAX);
        strncat (probe, exe, PATH_MAX);

        if (access (probe, X_OK) == 0) {
            printf("%s\n", probe);
            break;
        }
    }

    if (strncmp("./", exe, 2) == 0)
        if (access (exe, X_OK) == 0)
            printf("%s\n", exe);

    free(PATH);
    return;
}


void builtin_execute (Task T)
{
    unsigned int t = 1;

    if (!strcmp (T.cmd, "exit")) {
        exit (EXIT_SUCCESS);
    }
    
    else if (!strcmp (T.cmd, "which")) {
        while (T.argv[t] != NULL) {
            if (!is_builtin(T.argv[t])) {
                builtin_which(T.argv[t]);
            }
    
            else {
                printf("%s: shell built-in command\n", T.argv[t]);
            }
            
            t++;
        }
    }
    
    else if (!strcmp (T.cmd, "fg")) {
        if (T.argv[1] != NULL && T.argv[1][0] == '%') {
            builtin_fg(T.argv[1] + 1);
        }
        
        else {
            printf("Usage: fg %c<job number>\n", '%');
        }
    }

    else if (!strcmp (T.cmd, "bg")) {
        if (T.argv[1] != NULL && T.argv[1][0] == '%') {
            builtin_bg(T.argv[1] + 1);
        }
        
        else {
            printf("Usage: bg %c<job number>\n", '%');
        }
    }
    
    else if (!strcmp (T.cmd, "jobs")) {
        builtin_jobs(T.argv[0]);
    }

     
    else if (!strcmp (T.cmd, "kill")) {
        while (T.argv[t] != NULL) {
            t++;
        }
        
        builtin_kill(T.argv, t);
    }

    else if (!strcmp (T.cmd, "W"))
        print_W();

    else {
        printf ("pssh: built-in command: %s (not implemented!)\n", T.cmd);
    }
}


/* Called upon receiving a successful parse.
 * This function is responsible for cycling through the
 * tasks, and forking, executing, etc as necessary to get
 * the job done! */
void execute_job (Parse* P) 
{
    unsigned int t;
    pid_t pid;
    int fdin, fdout, fd[2], fdshell, job_id;
    Job job;

    fdin = STDIN_FILENO;
    if (P->infile) {
        fdin = open(P->infile, O_RDONLY);
    }

    fdout = STDOUT_FILENO;
    if (P->outfile) {
        fdout = open(P->outfile, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    }


    /* prevent undefined behaviors upfront */
    for (t = 0; t < P->ntasks; t++) {
        if (is_builtin(P->tasks[t].cmd) && P->ntasks > 1) {
            printf("pssh: no built-in pipelining\n");
            return;
        }
    }
    
    if ((job_id = insert_job(job)) < 0) {
        /* allow built-in commands to manage jobs*/
        if (is_builtin(P->tasks[0].cmd)) {
            fdshell = dup(STDOUT_FILENO);
            redirect(fdout, STDOUT_FILENO);
            builtin_execute(P->tasks[0]);
            redirect(fdshell, STDOUT_FILENO);
        }
        
        else {
            printf("pssh: maximum number of jobs supported reached\n");
        }
      
        return;
    }

    jobs[job_id].pids = (int*)malloc(sizeof(int) * P->ntasks);
    jobs[job_id].name = malloc(strlen(P->cmdline) + 1);
    strcpy(jobs[job_id].name, P->cmdline); 
    
    for (t = 0; t < P->ntasks; t++) {
        if (is_builtin(P->tasks[t].cmd)) {
            remove_job(job_id);
            
            if (P->background) printf("pssh: no built-in background\n");
            
            fdshell = dup(STDOUT_FILENO);
            redirect(fdout, STDOUT_FILENO);
            builtin_execute(P->tasks[t]);
            redirect(fdshell, STDOUT_FILENO);
            return;
        }
        
        else if (command_found(P->tasks[t].cmd)) {
            if (t == P->ntasks-1) {
                if ((pid = fork()) == -1) {
                    print_ferror(errno);    
                    break;
                }
                
                set_job_pgid(pid, job_id);

                /* child process */
                if (pid == 0) {
                    signal (SIGINT, SIG_DFL);
                    signal (SIGQUIT, SIG_DFL);
                    signal (SIGTSTP, SIG_DFL);
                    signal (SIGTTIN, SIG_DFL);
                    signal (SIGTTOU, SIG_DFL);
                    signal (SIGCHLD, SIG_DFL); 
                    
                    execute_process(P->tasks[t].argv, fdin, fdout);
                }
                
                /* parent process */
                else {
                    *(jobs[job_id].pids + t) = pid;
                    jobs[job_id].npids++;
                }
            }
        
            else {
                pipe(fd);
                if ((pid = fork()) == -1) {
                    print_ferror(errno);    
                    break;
                }
    
                set_job_pgid(pid, job_id);
                
                /* child process */
                if (pid == 0) {
                    signal (SIGINT, SIG_DFL);
                    signal (SIGQUIT, SIG_DFL);
                    signal (SIGTSTP, SIG_DFL);
                    signal (SIGTTIN, SIG_DFL);
                    signal (SIGTTOU, SIG_DFL);
                    signal (SIGCHLD, SIG_DFL); 
                    
                    close(fd[0]);
                    execute_process(P->tasks[t].argv, fdin, fd[1]);
                }
                
                /* parent process */
                else {
                    *(jobs[job_id].pids + t) = pid;
                    jobs[job_id].npids++;

                    close(fd[1]);
                    fdin = fd[0];
                }
            }
        }
        
        else {
            printf("pssh: command not found: %s\n", P->tasks[t].cmd);
            return;
        }
	}

    signal(SIGTTOU, handler_sigttou);
    signal(SIGCHLD, handler_sigchld);

    if (!P->background) {
        set_job_status(job_id, FG);
        put_pgid_in_foreground(jobs[job_id].pgid);
    }

    else {
        set_job_status(job_id, BG);
        print_job_pids(job_id);
    }
}


int main (int argc, char** argv)
{
    char* cmdline;
    Parse* P;

    shell_terminal = STDIN_FILENO;

    while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
        kill(-shell_pgid, SIGTTIN);

    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    shell_pgid = getpid();
    setpgid(shell_pgid, shell_pgid);
    tcsetpgrp(shell_terminal, shell_pgid);
    
    print_banner();

    while(1) {
        cmdline = readline (build_prompt());
        if (!cmdline)       /* EOF (ex: ctrl-d) */
            exit (EXIT_SUCCESS);

        P = parse_cmdline (cmdline);
        if (!P)
            goto next;

        if (P->invalid_syntax) {
            printf ("pssh: invalid syntax\n");
            goto next;
        }

    #if DEBUG_PARSE
        parse_debug (P);
    #endif

        execute_job (P);

    next:
        parse_destroy (&P);
        free(cmdline);
    }

    return EXIT_SUCCESS;
}
