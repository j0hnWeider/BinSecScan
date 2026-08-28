#include "parser_elf.h"
#include "entropy.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>      // <-- ESSENCIAL: define uint16_t, uint32_t, uint64_t
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// ------------------------------------------------------------
// Definições manuais das estruturas ELF
// 
// Minha ideia aqui é evitar depender do elf.h do sistema,
// que pode não existir no macOS ou Windows.
// Usei as definições padrão de 64 bits (Elf64) que são as mais comuns.
// Se um dia precisar de suporte a 32 bits, adapto.
// ------------------------------------------------------------

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFMAG "\177ELF"
#define SELFMAG 4

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

#define MIN_STRING_LEN 8

static void check_buffer_entropy(const unsigned char *buf, size_t len, double threshold, const char *context) {
    if (len < MIN_STRING_LEN) return;
    
    double ent = calculate_shannon_entropy(buf, len);
    if (ent > threshold) {
        printf("[ALERTA] Alta entropia detectada (%.2f) em %s\n", ent, context);
        printf("  Conteudo: ");
        for (size_t i = 0; i < len && i < 32; i++) {
            if (isprint(buf[i])) putchar(buf[i]);
            else putchar('.');
        }
        printf("\n");
    }
}

int analyze_elf(const char *filepath, double threshold) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("Erro ao abrir arquivo");
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    unsigned char *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        return -1;
    }

    // Valida magic number ELF
    if (st.st_size < sizeof(Elf64_Ehdr) ||
        map[0] != ELFMAG0 || map[1] != ELFMAG1 ||
        map[2] != ELFMAG2 || map[3] != ELFMAG3) {
        munmap(map, st.st_size);
        close(fd);
        fprintf(stderr, "Arquivo nao e um ELF valido.\n");
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
    char *shstrtab = (char *)(map + shdr[ehdr->e_shstrndx].sh_offset);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *sec_name = shstrtab + shdr[i].sh_name;
        
        // Adicionei .rdata, .strtab e .dynstr pq eles tambem podem ter strings
        if (strcmp(sec_name, ".rodata") == 0 || 
            strcmp(sec_name, ".data") == 0 || 
            strcmp(sec_name, ".rdata") == 0 ||
            strcmp(sec_name, ".strtab") == 0 ||
            strcmp(sec_name, ".dynstr") == 0) {
            
            unsigned char *sec_data = map + shdr[i].sh_offset;
            size_t sec_size = shdr[i].sh_size;
            
            size_t start = 0;
            for (size_t j = 0; j < sec_size; j++) {
                if (isprint(sec_data[j]) && sec_data[j] != ' ') {
                    if (start == 0) start = j;
                } else {
                    if (start != 0) {
                        size_t len = j - start;
                        if (len >= MIN_STRING_LEN) {
                            char ctx[256];
                            snprintf(ctx, sizeof(ctx), "%s:offset_%lu", sec_name, start);
                            check_buffer_entropy(&sec_data[start], len, threshold, ctx);
                        }
                        start = 0;
                    }
                }
            }
            if (start != 0) {
                size_t len = sec_size - start;
                if (len >= MIN_STRING_LEN) {
                    char ctx[256];
                    snprintf(ctx, sizeof(ctx), "%s:offset_%lu", sec_name, start);
                    check_buffer_entropy(&sec_data[start], len, threshold, ctx);
                }
            }
        }
    }

    munmap(map, st.st_size);
    close(fd);
    return 0;
}