#include "parser_pe.h"
#include "entropy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>      // <-- ESSENCIAL: define uint16_t, uint32_t, etc.
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

// Estruturas do PE (mantive as mesmas)
#pragma pack(push, 1)
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} DOS_HEADER;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFF_HEADER;

typedef struct {
    char Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SECTION_HEADER;
#pragma pack(pop)

#define MIN_STRING_LEN 8

static void check_pe_buffer(const unsigned char *buf, size_t len, double threshold, const char *sec_name, uint32_t offset) {
    if (len < MIN_STRING_LEN) return;
    
    double ent = calculate_shannon_entropy(buf, len);
    if (ent > threshold) {
        printf("[ALERTA] Alta entropia detectada (%.2f) em PE:%s:offset_%u\n", ent, sec_name, offset);
        printf("  Conteudo: ");
        for (size_t i = 0; i < len && i < 32; i++) {
            if (isprint(buf[i])) putchar(buf[i]);
            else putchar('.');
        }
        printf("\n");
    }
}

int analyze_pe(const char *filepath, double threshold) {
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

    if (st.st_size < sizeof(DOS_HEADER)) {
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    DOS_HEADER *dos_hdr = (DOS_HEADER *)map;
    if (dos_hdr->e_magic != 0x5A4D) {
        munmap(map, st.st_size);
        close(fd);
        fprintf(stderr, "Arquivo nao e um PE valido (Magic MZ ausente).\n");
        return -1;
    }

    int pe_offset = dos_hdr->e_lfanew;
    if (pe_offset + sizeof(uint32_t) + sizeof(COFF_HEADER) > st.st_size) {
        munmap(map, st.st_size);
        close(fd);
        return -1;
    }

    COFF_HEADER *coff_hdr = (COFF_HEADER *)(map + pe_offset + 4);
    SECTION_HEADER *sections = (SECTION_HEADER *)(map + pe_offset + 4 + sizeof(COFF_HEADER) + coff_hdr->SizeOfOptionalHeader);

    for (int i = 0; i < coff_hdr->NumberOfSections; i++) {
        if (strncmp(sections[i].Name, ".rdata", 6) == 0 || 
            strncmp(sections[i].Name, ".data", 5) == 0 ||
            strncmp(sections[i].Name, ".text", 5) == 0) {
            
            uint32_t raw_ptr = sections[i].PointerToRawData;
            uint32_t raw_size = sections[i].SizeOfRawData;

            if (raw_ptr + raw_size > st.st_size) continue;

            unsigned char *sec_data = map + raw_ptr;
            
            size_t start = 0;
            for (uint32_t j = 0; j < raw_size; j++) {
                if (isprint(sec_data[j]) && sec_data[j] != ' ') {
                    if (start == 0) start = j;
                } else {
                    if (start != 0) {
                        size_t len = j - start;
                        if (len >= MIN_STRING_LEN) {
                            check_pe_buffer(&sec_data[start], len, threshold, sections[i].Name, raw_ptr + start);
                        }
                        start = 0;
                    }
                }
            }
            if (start != 0) {
                size_t len = raw_size - start;
                if (len >= MIN_STRING_LEN) {
                    check_pe_buffer(&sec_data[start], len, threshold, sections[i].Name, raw_ptr + start);
                }
            }
        }
    }

    munmap(map, st.st_size);
    close(fd);
    return 0;
}