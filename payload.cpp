#include <stddef.h>
#include <stdio.h>
#include <asm/unistd_64.h>

volatile int __always_false;

#define PAYLOAD_PROLOGUE __always_false = 0; \
     if (__always_false) { \
          start:

#define PAYLOAD_EPILOGUE  end: (void) 0; \
     } \
     void *start_v = &&start; \
     void *end_v = &&end; \
     *sz = (char *) end_v - (char *) start_v; \
     return start_v;


extern "C" void* PayloadTrampHello(size_t* sz) {
     PAYLOAD_PROLOGUE
     asm __volatile__ (//"xchg %%rax,%%rax"
     "pushq %%rax\n"
     "pushq %%rdi\n"
     "pushq %%rsi\n"
     "pushq %%rdx\n"
     "movq $1, %%rax\n"
     "pushq $0x000a4948\n"
     "movq $1, %%rdi\n"
     "movq %%rsp, %%rsi\n"
     "movq $3,%%rdx\n"
     "syscall\n"
     "addq $8, %%rsp\n"
     "popq %%rdx\n"
     "popq %%rsi\n"
     "popq %%rdi\n"
     "popq %%rax\n"

     //здесь мы должны что-то записать в канал в направлении родителя, дескриптор 511
     :::);
     PAYLOAD_EPILOGUE
}

extern "C" void* PAYLOAD_AMD64_MMAP(size_t* sz) { // (char* mem, int len, int val) {
     PAYLOAD_PROLOGUE
     asm __volatile__ ( "int $3\n\
     movq $0x10000, %%rdi\n\
     movq $4096, %%rsi\n\
     movq $0x5, %%rdx\n\
     movq $0x12, %%r10\n\
     movq $512, %%r8\n\
     movq $0, %%r9\n\
     movq $9, %%rax\n\
     syscall\n\
     int $3\n" ::: "%rdi", "%rsi", "%rdx", "%r10", "%r8", "%r9", "%rax");
     PAYLOAD_EPILOGUE
}
