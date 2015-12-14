#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <bits/stdc++.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>
#include <stab.h>

class elf_file {
public:
    int fd_;
    size_t size_;
    char * ptr_;
    elf_file (const char* filename) {
        fd_ = open(filename, O_RDONLY);
        struct stat buf;
        fstat(fd_, &buf);
        size_ = buf.st_size;
        ptr_ = (char *)mmap(NULL, size_, PROT_READ, MAP_SHARED, fd_, 0);
    }
    ~elf_file () {
        munmap (ptr_, size_);
        close(fd_);
    }

    elf_file(const elf_file&) = delete;
    void operator=(const elf_file&) = delete;
    elf_file(elf_file&&) = delete;
};

struct function {
    std::string name;
    int index;
    const char* source;
    uintptr_t start;
    uintptr_t end;
};


bool comp(const function & f1, const function & f2){
    int ind = strcmp(f1.name.c_str(), f2.name.c_str());
    return ind ? (ind < 0) : f1.start < f2.start;
}

Elf64_Shdr * find_shader(const elf_file & Elf, const Elf64_Ehdr * header, const char * names, const char* Fname) {
    for (uintptr_t i = 1; i < header->e_shnum; i++) {
        Elf64_Shdr * elem_shader = (Elf64_Shdr *) (Elf.ptr_ + (header->e_shoff + i * sizeof(Elf64_Shdr)));
        const char *name = names + elem_shader->sh_name;
        if (!strcmp(name, Fname)) {
//            printf("%s 0x%x\n", Fname, (uint32_t)elem_shader);
            return elem_shader;
        }
    }
    return NULL;
}


void listing(const Elf64_Sym * sym, const size_t size, const char * strtab) {
    Elf64_Sym *current = (Elf64_Sym *) sym;
    for (int i = 0; current < sym + size / sizeof(Elf64_Sym); current++, i++) {
        //printf("0x%x\n", current->st_info);
        switch (ELF64_ST_TYPE(current->st_info)) {
            case STT_FUNC:
                //    printf("0x%lx\n", (unsigned long)current);
                printf("%s %s 0x%lx\n", "func", strtab + current->st_name, current->st_value);
                break;
                //default:
                //    printf("%s 0x%lx\n", "not for us\n", current->st_value);
        }
    }
}

int main(int argc, char** argv) {
    elf_file Elf(argv[1]);

    Elf64_Ehdr * header = (Elf64_Ehdr *)Elf.ptr_;
    Elf64_Shdr * shader_table_name = (Elf64_Shdr *)(Elf.ptr_ + (header->e_shoff + header->e_shstrndx * header->e_shentsize));
    char * names = (Elf.ptr_ + shader_table_name->sh_offset);
    Elf64_Shdr * symtab_shader = find_shader(Elf, header, names, ".symtab");
    Elf64_Shdr * strtab_shader = find_shader(Elf, header, names, ".strtab");
    if (symtab_shader == NULL || strtab_shader == NULL) {
        printf("%s\n", "No debug info");
        return 0;
    }
    Elf64_Sym * symtab = (Elf64_Sym *)(Elf.ptr_ + symtab_shader->sh_offset);
    char * strtab = (Elf.ptr_ + strtab_shader->sh_offset);
    //std::cout << stabptr << std::endl;
    size_t symtabsize = (symtab_shader->sh_size);
    size_t strsize = (strtab_shader->sh_size);
   // printf("%s 0x%lx %s %lu %s 0x%lx %s %lu\n", ".symtab", (uintptr_t)symtab - (uintptr_t)Elf.ptr_, "size: ", symtabsize, \
           ".strtab", (uintptr_t)strtab - (uintptr_t)Elf.ptr_, "size: ", strsize);
    /*std::string tabword = "";
    char * current = strtab;
    for (int i = 0; i < strsize; ) {
        while (*current != '\0') {
            tabword += *current;
            current++;
        }
        i += tabword.size() + 1;
        std::cout << i << tabword << std::endl;
        tabword = "";
        current++;
    }*/

    listing(symtab, symtabsize, strtab);
    return 0;
}
