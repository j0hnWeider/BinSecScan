#include "parser_elf.h"
#include "entropy.h"
#include <stdlib.h>
#include <string.h>
#include <elf.h> // Cabeçalhos padrão do Linux para ELF
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Tamanho mínimo de string candidata para análise
#define MIN_STRING_LEN 8

static void check_buffer_entropy(const unsigned char *buf, size_t len, double threshold, const char *context) {
    if (len < MIN_STRING_LEN) return;
    
    double ent = calculate_shannon_entropy(buf, len);
    if (ent > threshold) {
        printf("[ALERTA] Alta entropia detectada (%.2f) em %s\n", ent, context);
        // Imprime os primeiros bytes para contexto (sanitizado para não quebrar terminal)
        printf("  Conteúdo: ");
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

    // Validação básica de magic number ELF
    if (st.st_size < sizeof(Elf64_Ehdr) || memcmp(map, ELFMAG, SELFMAG) != 0) {
        munmap(map, st.st_size);
        close(fd);
        fprintf(stderr, "Arquivo não é um ELF válido.\n");
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)map;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(map + ehdr->e_shoff);
    char *shstrtab = (char *)(map + shdr[ehdr->e_shstrndx].sh_offset);

    // Itera sobre as seções procurando por .rodata, .data, .strings
    for (int i = 0; i < ehdr->e_shnum; i++) {
        char *sec_name = shstrtab + shdr[i].sh_name;
        
        // Foca em seções que geralmente contêm strings constantes
        if (strcmp(sec_name, ".rodata") == 0 || strcmp(sec_name, ".data") == 0) {
            unsigned char *sec_data = map + shdr[i].sh_offset;
            size_t sec_size = shdr[i].sh_size;
            
            // Varre a seção procurando por sequências de bytes imprimíveis
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
            // Caso a seção termine com uma string válida
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
