#define _POSIX_C_SOURCE 200809
#undef _GNU_SOURCE
#include <bits/stdc++.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "readsys.h"
#include "amd64.h"

extern "C" {

#include "udis86/libudis86/types.h"
#include "udis86/libudis86/extern.h"
#include "udis86/libudis86/itab.h"

}
using namespace as;
//struct fun_info {
//    const char * name;
//    uintptr_t start;
//};

size_t find_len (const char* name, char *buf, size_t sb) {
	ud_t ud_obj;
	ud_init(&ud_obj);
	ud_set_syntax(&ud_obj, ud_translate_att);
	ud_set_mode(&ud_obj, 64);
	ud_set_input_buffer(&ud_obj, (unsigned char *)buf, sb);
	size_t len = 0;
	printf("%s\n", name);
	while (len < 5) {
		int d = ud_disassemble(&ud_obj);
		printf("\t%s\n", ud_insn_asm(&ud_obj));
		if (!(ud_obj.mnemonic == UD_Imov || ud_obj.mnemonic == UD_Ipush || ud_obj.mnemonic == UD_Iadd || ud_obj.mnemonic == UD_Isub)) {
			printf(" = bad instr\n");
			return 0;
		}
		for (auto o:ud_obj.operand) {
			if (o.type == UD_R_RIP || o.base == UD_R_RIP || o.index == UD_R_RIP) {
				printf(" = RIP\n");
				return 0;
			}
		}
		if (d <= 0) {
			printf(" = badlen\n");
			return 0;
		}
		len += d;
	}
	return len;
}

void fullwrite(int fd, char *buf, int len) {
    size_t size = 0;
    while (size < len)
        size += write(fd, buf + size, len - size);
}

void print_info(int fd, std::map<uintptr_t, const char*> &symtab) {
	uintptr_t buf;
	while (read(fd, &buf, 4) == 4) {
		auto it = symtab.find(buf);
		if (it == symtab.end()) {
			std::cout << "unknown adress " << std::hex << buf << std::dec << std::endl;
		} else {
			std::cout << it->second << " " << std::hex << buf << std::dec << std::endl;
			sleep(1);
		}
	}
}

//void patch_function()


// Нам понадобится обработка ошибок. Чтобы не писать её на каждый чих, заведём пару полезных функций

// Эта функция печатает сообщение об ошибке и сообщает, в каком контексте эта ошибка случилась
void print_error_and_exit(const char* msg, const char* err, const char* file, int line) {
    char buf[1024];
    const char* fname = strrchr(file, '/');
    fname = fname ? fname + 1 : file;

    snprintf(buf, sizeof(buf), "%s at %s:%d: %s\n", msg, fname, line, err);
    fflush(NULL);
    write(STDERR_FILENO, buf, strlen(buf));
    exit(1);
}

// Эта функция обеспечивает обработку ошибок системных вызовов и стандартной библиотеки C
void perror_and_exit(const char* msg, const char* file, int line) {
    char buf[1024];
    if (-1 == strerror_r(errno, buf, sizeof(buf))) {
        abort();
    }
    print_error_and_exit(msg, buf, file, line);
}

// Вспомогательный макрос, позволяет преобразовать произвольное выражение в строку
#define TO_STRING_IMPL(s) #s
#define TO_STRING(s) TO_STRING_IMPL(s)

// Макрос, позволяющий сократить код проверки на ошибки, принимает 2 аргумента: выражение и условие, когда оно сфейлилось
// Например:
// ASSERT_SYSCALL(int fd = open(name, O_RDONLY, 0), -1 != fd);
// - открыть файл или умереть, рассказав подробно перед смертью, что пошло не так
#ifndef ASSERT_SYSCALL
#   define ASSERT_SYSCALL(call, ok_cond) errno = 0; call; do { if (!(ok_cond)) { \
        perror_and_exit("failed " TO_STRING(call), __FILE__, __LINE__); \
    } } while(0)
#else
#   error "ASSERT_SYSCALL already defined"
#endif

// Аналогичный ASSERT_SYSCALL макрос для прочих проверок, пофейлив которые нет смысла жить дальше
// Для удобства вывода отладочной инфы реализован через variadic macro
#ifndef ASSERT
#   define ASSERT(ok_cond, ...) do { if (!(ok_cond)) { \
        char err_buf[1024]; \
        snprintf(err_buf, sizeof(err_buf), __VA_ARGS__); \
        print_error_and_exit("failed check " TO_STRING(ok_cond), err_buf, __FILE__, __LINE__); \
    } } while(0)
#else
#   error "ASSERT already defined"
#endif
// Это на самом деле тупо два указателя на начало и конец кода для инъекции, см. payload.S
extern "C" void* PAYLOAD_AMD64_MMAP(size_t*);
extern "C" void* PayloadTrampHello(size_t* sz);

// Макрос для округления размера в большую сторону
#define ALIGN_UP(size, alignment) (((size) + (alignment) - 1) / (alignment) * (alignment))

// Макрос для вычисления размера массива
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

// Код мы будем внедрять прямо в точку входа, и нам нужно найти её адрес.
int64_t get_x86_64_linux_victim_entry_point(const char* name) {
    int res;
    ASSERT_SYSCALL(int fd = open(name, O_RDONLY), -1 != fd);

    // отмапим файл в память, убедимся, что он непустой
    struct stat st;
    ASSERT_SYSCALL(res = fstat(fd, &st), -1 != res);
    ASSERT(st.st_size, "not an ELF");
    ASSERT_SYSCALL(void* fmem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0), NULL != fmem);

    // интерпретируем начало файла как заголовок эльфа
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)fmem;
    const char* ident = (const char*)ehdr->e_ident;

    // проверим, что правда эльф и тот что надо эльф
    ASSERT(!strncmp(ident, ELFMAG, SELFMAG), "not an ELF");
    ASSERT(ELFCLASS64 == ident[EI_CLASS], "unsupported ELF");
    ASSERT(ELFDATA2LSB == ident[EI_DATA], "unsupported ELF");
    ASSERT(ELFOSABI_SYSV == ident[EI_OSABI] ||
           ELFOSABI_LINUX == ident[EI_OSABI], "unsupported ELF");
    ASSERT(0 == ident[EI_ABIVERSION], "unsupported ELF");
    ASSERT(EM_X86_64 == ehdr->e_machine, "unsupported ELF");
    ASSERT(ET_EXEC == ehdr->e_type,"unsupported ELF");
    ASSERT(0 != ehdr->e_entry, "unsupported ELF");

    int64_t entry = ehdr->e_entry;

    ASSERT_SYSCALL(res = munmap(fmem, st.st_size), -1 != res);
    ASSERT_SYSCALL(res = close(fd), -1 != res);

    return entry;
}

int main(int argc, char** argv) {
	elf_file Elf(argv[1]);
	std::map<uintptr_t, const char*> symtab = readsys(Elf);
    for (auto item : symtab) {
        printf("0x%lx %s\n", item.first, item.second);
    }
    int fds[2];
    pipe(fds);
    int fd = open("code", O_CREAT | O_RDWR | O_TRUNC, 0777);
    dup2(fd, 512);
    // Вот тут в будущем нужна нормальная обработка параметров командной строки, но пока так
    if (argc < 2 || !strcmp(argv[1], "--help")) {
        printf("usage: %s <tracee> <tracee options>...\n", argv[0]);
        exit(0);
    }

    // имя программы, в которую будем инжектировать код
    char* victim_name = argv[1];
    // все параметры передаём в программу
    int victim_argc = argc - 1;
    char** victim_argv = argv + 1;

    // отпочковываем процесс, в котором запустим жертву
    ASSERT_SYSCALL(pid_t child = fork(), -1 != child);
    if (0 == child) {
        dup2(fds[1], 511);
        close(fds[0]);
        close(fds[1]);
        // Переводим ребёнка в режим трассировки. Ребёнок остановится сразу после запуска.
        ASSERT_SYSCALL(long res_ptrace = ptrace(PTRACE_TRACEME), -1 != res_ptrace || !errno);
        // Превращаем ребёнка в будущую жертву инъекций
        ASSERT_SYSCALL(int res_execle = execvp(victim_name, victim_argv), -1 != res_execle);
    } else {
        close(fds[1]);
        int wait_status;
        long res_ptrace;
        pid_t res_wait;

        // Ждём, пока жертва остановится.
        ASSERT_SYSCALL(res_wait = waitpid(child, &wait_status, 0), -1 != res_wait);

        // Ребёнок не остановился, вместо этого с ним случилась какая-то другая фигня
        ASSERT(WIFSTOPPED(wait_status), "unexpected status (%d)", wait_status);

        // Получаем точку входа жертвы
        const int64_t entry = get_x86_64_linux_victim_entry_point(victim_name);
// прыгаем из функции в трамплин который напишем дальше в ту память которая уже замаплена
        // saving main prologue
        const uintptr_t inj_begin = 0x10000;
        code co;
        for (auto item:symtab){
            uintptr_t tramp_addr = inj_begin + co.size();
            uintptr_t funcptr = item.first;
            const int bufcnt = 4;
            long prologue[bufcnt]; // 32 bytes
            // find length
            for(int i = 0; i < ARRAY_SIZE(prologue); i++) {
            	prologue[i] = ptrace(PTRACE_PEEKTEXT, child, funcptr + sizeof(long) * i, NULL);
            }

            int prologue_len = find_len(item.second, (char*)prologue, sizeof(prologue));

            if (prologue_len < 5) {
            	std::cout << "skip this func: " << item.second << " " << item.first << std::endl;
            	continue;
            }

            char jump[sizeof(prologue)];
            memcpy(jump, prologue, sizeof(prologue));
            jump[0] = 0xe9;
            uintptr_t func2tramp_off = tramp_addr - (funcptr + 5);
            memcpy(jump + 1, &func2tramp_off, 4);

            for(int i = 0; i < 2; i++) {
            	long p;
            	memcpy(&p, jump + i * sizeof(long), sizeof(long));
            	ptrace(PTRACE_POKETEXT, child, (void*)(funcptr + sizeof(long) * i), (void*)p);
            }

        //готовим файлик который хочется замапить, и канал между ребенком и отцом

            close(fd);
            close(fds[1]);

//        char *tramp_ptr = (char*)PayloadTrampHello(&tramp_size);
            co.push(rax)
        		.push(rdi)
        		.push(rsi)
        		.push(rdx)
        		.mov((i32)1, rax)
        		.push((i32)funcptr)
        		.mov((i32)511, rdi)
        		.mov(rsp, rsi)
        		.mov((i32)4, rdx)
        		.syscall()
        		.add((i32)8, rsp)
        		.pop(rdx)
        		.pop(rsi)
        		.pop(rdi)
        		.pop(rax)
        		.append(prologue, prologue_len);

            char epilogue[5];
            epilogue[0] = 0xe9;

            uintptr_t tramp2func_off = funcptr + prologue_len - (inj_begin + co.size() + 5);
            memcpy(epilogue + 1, &tramp2func_off, 4);
            co.append(epilogue, 5);
        //здесь надо взять адрес функции, положить его на стек
        //потом позвать какую-то функцию, которую надо написать в трамплин в начало(на адрес 0х10000)
        //починить стек
        //все это надо просто взять определённым машинным кодом, который надо скомпилировать отдельно и потом \
        брать и менять только адрес при записи в наш бинарник, который мы будем мапить

        }

        fullwrite(512, (char*)co.data(), co.size());

        //fsync(512);
        /*for(int i = 0; i < 2; ++i) { // sizeof(long)
            long p;
            memcpy(&p, tramplin_end + i * sizeof(long), sizeof(long));
            ptrace(PTRACE_POKETEXT, child, mem + sizeof(long) * i, (void*)p);
        }*/

        code c;
        c.brkp().syscall().brkp();

        size_t size = c.size();
        //void *payload_ptr = PAYLOAD_AMD64_MMAP(&payload_size);
        // Нам нужно сохранить код, который мы сейчас затрём в жертве.
        // Для этого заведём буфер достаточного размера и наполним его смыслом.
        long victim_text[ALIGN_UP(size, sizeof(long)) / sizeof(long)];
        // Также нам понадобится сохранять и восстанавливать регистры.
        struct user_regs_struct victim_regs;


        // Сразу скопируем инжектируемый код в массив, чтобы дальше просто поменять местами его с кодом жертвы
        memcpy(victim_text, c.data(), size);
//        victim_text[0] = 0xcc;
//        victim_text[1] = 0x05;
//        victim_text[2] = 0x0f;
//        victim_text[3] = 0xcc;


        // Меняем по sizeof(long) байт, так уж ptrace работает
        for (size_t i = 0; i < ARRAY_SIZE(victim_text); ++i) {
            void* addr = (char*)entry + sizeof(long) * i;
            void* data = (void*)victim_text[i];

            ASSERT_SYSCALL(long victim_word = ptrace(PTRACE_PEEKTEXT, child, addr, NULL), -1 != victim_word || !errno);
            ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_POKETEXT, child, addr, data), -1 != res_ptrace);
            victim_text[i] = victim_word;
        }
        // Отпускаем жертву до первого брейкпоинта (xCC в инъекции)
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_CONT, child, NULL, NULL), -1 != res_ptrace);

        // Ловим жертву на первом брейкпоинте
        do {
            ASSERT_SYSCALL(res_wait = waitpid(child, &wait_status, 0), -1 != res_wait);
            // Если пациент умер, мы вслед за ним
            ASSERT(!WIFSIGNALED(wait_status), "child died with signal %d", WTERMSIG(wait_status));
        } while (!WIFSTOPPED(wait_status));

        // Сохраняем регистры жертвы
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_GETREGS, child, NULL, &victim_regs), -1 != res_ptrace);
        struct user_regs_struct inject_regs = victim_regs;
        inject_regs.rax = 9;
        inject_regs.rdx = 0x5;
        inject_regs.rdi = 0x10000;
        inject_regs.rsi = 0x1000;
        inject_regs.r9 = 0;
        inject_regs.r10 = 0x12;
        inject_regs.r8 = 0x200;
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_SETREGS, child, NULL, &inject_regs), -1 != res_ptrace);


        // Отпускаем жертву до второго брейкпоинта (xCC в инъекции)
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_CONT, child, NULL, NULL), -1 != res_ptrace);

        // Ловим жертву на втором брейкпоинте
        // Если всё прошло как надо, к этому моменту жертва должна напечатать нам, то, что мы в неё наинжектили
        do {
            ASSERT_SYSCALL(res_wait = waitpid(child, &wait_status, 0), -1 != res_wait);
            ASSERT(!WIFSIGNALED(wait_status), "child died with signal %d", WTERMSIG(wait_status));
        } while (!WIFSTOPPED(wait_status));

        struct user_regs_struct regs;
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_GETREGS, child, NULL, &regs), -1 != res_ptrace);
        printf("rax = 0x%016llx\n", regs.rax);


        if (regs.rax != 0x10000) {
            std::cout << "fail" << std::endl;
            return 0;
        }
        //uintptr_t mem = regs.rax;
        //uintptr_t mem = 0x10000;
        // Чиним код жертвы
        for (size_t i = 0; i < ARRAY_SIZE(victim_text); ++i) {
            void *addr = (char *) entry + sizeof(long) * i;
            void *data = (void *) victim_text[i];

            ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_POKETEXT, child, addr, data), -1 != res_ptrace);
        }

        // Но нужно ещё починить rip жертвы, он смотрит на следующую инструкцию после брейкпоинта
        // Сделаем, чтобы rip смотрел на точку входа.
        victim_regs.rip = entry;
        // Чиним регистры жертвы
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_SETREGS, child, NULL, &victim_regs), -1 != res_ptrace);


        // Отпускаем жертву в свободное плавание
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_DETACH, child, NULL, NULL), -1 != res_ptrace);
        print_info(fds[0], symtab);
        // Ждём завершения жертвы.
        // Если операция прошла успешнно, жертва должна напечатать,
        // что она там хотела нам напечатать изначально, и выйти без ошибок
        do {
            wait_status = 0;
            ASSERT_SYSCALL(res_wait = waitpid(child, &wait_status, 0), -1 != res_wait);
            ASSERT(!WIFSIGNALED(wait_status), "child died with signal %d", WTERMSIG(wait_status));
            ASSERT(!WIFSTOPPED(wait_status), "child stopped with signal %d", WSTOPSIG(wait_status));
        } while (!WIFEXITED(wait_status));
    }
}
