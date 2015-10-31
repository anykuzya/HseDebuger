#include "debuglib.h"
#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
struct debug_breakpoint_t {
    void* addr;
    unsigned orig_data;
};

void run_injector(pid_t child_pid) {
    const char str[] = "\xeb\x0b\x49\x20\x61\x6d\x20\x68\x65\x20\x68\x65\x72\x65\x0a\x00\xb8\x04\x00\x00\x00\xb9\x7a\x00\x40\x00\xba\x0b\x00\x00\x00\xcd\x80\xcc";
    //printf("%d\n", str[4]);
    int wait_status;
    procmsg("injector started\n");
    wait(&wait_status);
    printf("w: %x\n", wait_status);
    //long rip = get_child_eip(child_pid);
    long ripl = 0x400440;
    void * rip = (void*) ripl;
    debug_breakpoint* dbp1 = create_breakpoint(child_pid, rip);
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(&wait_status);
    disable_breakpoint(child_pid, dbp1);
    struct user_regs_struct old_regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &old_regs);

    char buf[sizeof(str)];
    printf("RIP: %08lx\n", (long)(rip));
    for (long i = 0; i < sizeof(str); ++i) {
        unsigned bytes = ptrace(PTRACE_PEEKTEXT, child_pid, rip + i, 0);
        buf[i] = bytes;
    }
    printf("mem:");
    for(int i = 0; i < 32; i++) {
        printf("%02x ", 0xff & *(buf + i)); 
    }
    printf("\nnew instr:");
    for (long i = 0; i <= sizeof(str)-sizeof(unsigned); ++i) {
        printf("%02x:", 0xff & *(str + i));
        ptrace(PTRACE_POKETEXT, child_pid, rip + i, str + i);
        printf("%02x ", 0xff & *(char*)(rip + i));
    }

    printf("\ni did byaka\n");
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(&wait_status);
    printf("i execute byaka\n");
    ptrace(PTRACE_SETREGS, child_pid, 0, &old_regs);
    for (long i = 0; i <= sizeof(str)-sizeof(unsigned); ++i) {
        ptrace(PTRACE_POKETEXT, child_pid, rip + i, buf + i);
    }
    printf("i restored\n");
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    printf("i finished\n");
}

int main(int argc, char** argv)
{
    pid_t child_pid;

    if (argc < 2) {
        fprintf(stderr, "Expected a program name as argument\n");
        return -1;
    }

    child_pid = fork();
    if (child_pid == 0)
        run_target(argv[1]);
    else if (child_pid > 0)
        run_injector(child_pid);
    else {
        perror("fork");
        return -1;
    }

    return 0;
}


