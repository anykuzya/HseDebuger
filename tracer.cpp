#define _POSIX_C_SOURCE 200809

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
extern void PAYLOAD_AMD64();
extern void PAYLOAD_AMD64_END();

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
    const char* ident = ehdr->e_ident;

    // проверим, что правда эльф и тот что надо эльф
    ASSERT(!strncmp(ident, ELFMAG, SELFMAG), "not an ELF");
    ASSERT(ELFCLASS64 == ident[EI_CLASS], "unsupported ELF");
    ASSERT(ELFDATA2LSB == ident[EI_DATA], "unsupported ELF");
    ASSERT(ELFOSABI_SYSV == ident[EI_OSABI] ||
           ELFOSABI_LINUX == ident[EI_OSABI], "unsupported ELF");
    ASSERT(0 == ident[EI_ABIVERSION], "unsupported ELF");
    ASSERT(EM_X86_64 == ehdr->e_machine, "unsupported ELF");
    ASSERT(ET_EXEC == ehdr->e_type, "unsupported ELF");
    ASSERT(0 != ehdr->e_entry, "unsupported ELF");

    int64_t entry = ehdr->e_entry;

    ASSERT_SYSCALL(res = munmap(fmem, st.st_size), -1 != res);
    ASSERT_SYSCALL(res = close(fd), -1 != res);

    return entry;
}

int main(int argc, char** argv) {
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
        // Переводим ребёнка в режим трассировки. Ребёнок остановится сразу после запуска.
        ASSERT_SYSCALL(long res_ptrace = ptrace(PTRACE_TRACEME), -1 != res_ptrace || !errno);
        // Превращаем ребёнка в будущую жертву инъекций
        ASSERT_SYSCALL(int res_execle = execvp(victim_name, victim_argv), -1 != res_execle);
    } else {
        int wait_status;
        long res_ptrace;
        pid_t res_wait;

        // Ждём, пока жертва остановится.
        ASSERT_SYSCALL(res_wait = waitpid(child, &wait_status, 0), -1 != res_wait);

        // Ребёнок не остановился, вместо этого с ним случилась какая-то другая фигня
        char * txt = (char*)f.ptr_;
        ASSERT(WIFSTOPPED(wait_status), "unexpected status (%d)", wait_status);

        // Получаем точку входа жертвы
        const int64_t entry = get_x86_64_linux_victim_entry_point(victim_name);

        const size_t payload_size = (const char*)PAYLOAD_AMD64_END - (const char*)PAYLOAD_AMD64;
        // Нам нужно сохранить код, который мы сейчас затрём в жертве.
        // Для этого заведём буфер достаточного размера и наполним его смыслом.
        long victim_text[ALIGN_UP(payload_size, sizeof(long)) / sizeof(long)];
        // Также нам понадобится сохранять и восстанавливать регистры.
        struct user_regs_struct victim_regs;

        // Сразу скопируем инжектируемый код в массив, чтобы дальше просто поменять местами его с кодом жертвы
        memcpy(victim_text, (void*)PAYLOAD_AMD64, payload_size);

        // Меняем по sizeof(unsigned) байт, так уж ptrace работает
        for (size_t i = 0; i < ARRAY_SIZE(victim_text); ++i) {
            void* addr = (void*)entry + sizeof(long) * i;
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

        // Но нужно ещё починить rip жертвы, он смотрит на следующую инструкцию после брейкпоинта
        // Сделаем, чтобы rip смотрел на точку входа.
        victim_regs.rip = entry;

        // Отпускаем жертву до второго брейкпоинта (xCC в инъекции)
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_CONT, child, NULL, NULL), -1 != res_ptrace);

        // Ловим жертву на втором брейкпоинте
        // Если всё прошло как надо, к этому моменту жертва должна напечатать нам, то, что мы в неё наинжектили
        do {
            ASSERT_SYSCALL(res_wait = waitpid(child, &wait_status, 0), -1 != res_wait);
            ASSERT(!WIFSIGNALED(wait_status), "child died with signal %d", WTERMSIG(wait_status));
        } while (!WIFSTOPPED(wait_status));

        // Чиним код жертвы
        for (size_t i = 0; i < ARRAY_SIZE(victim_text); ++i) {
            void* addr = (void*)entry + sizeof(long) * i;
            void* data = (void*)victim_text[i];

            ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_POKETEXT, child, addr, data), -1 != res_ptrace);
        }

        // Чиним регистры жертвы
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_SETREGS, child, NULL, &victim_regs), -1 != res_ptrace);

        // Отпускаем жертву в свободное плавание
        ASSERT_SYSCALL(res_ptrace = ptrace(PTRACE_CONT, child, NULL, NULL), -1 != res_ptrace);

        // Ждём завершения жертвы.
        // Если операция прошла успешнно, жертва должна напечатать,
        // что она там хотела нам напечатать изначально, и выйти без ошибок
        do {
            ASSERT_SYSCALL(res_wait = waitpid(child, &wait_status, 0), -1 != res_wait);
            ASSERT(!WIFSIGNALED(wait_status), "child died with signal %d", WTERMSIG(wait_status));
        } while (!WIFEXITED(wait_status));
    }
}
