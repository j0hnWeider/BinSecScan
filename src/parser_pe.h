#ifndef PARSER_PE_H
#define PARSER_PE_H

// Analisa um arquivo PE (Windows) e extrai strings da seção .rdata ou .data
int analyze_pe(const char *filepath, double threshold);

#endif
