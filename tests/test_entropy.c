/**
 * Testes para o modulo de entropia
 *
 * Minha ideia aqui é validar que a funcao calculate_shannon_entropy
 * se comporta como esperado em diferentes cenarios.
 * Usei o framework Criterion pq ele é simples e nao precisa de muita
 * configuracao. Futuramente posso adicionar mais testes pros parsers,
 * mas por enquanto vou focar so na entropia.
 */

#include <criterion/criterion.h>
#include <string.h>
#include "../entropy.h"

/**
 * Teste: buffer com todos os bytes zerados
 * 
 * Se todos os bytes sao iguais, a entropia deve ser 0.0
 * Isso pq a probabilidade de cada byte é 1 (100%), entao -1 * log2(1) = 0
 */
Test(entropy, zero_bytes) {
    unsigned char buf[10] = {0};
    double e = calculate_shannon_entropy(buf, 10);
    cr_assert_float_eq(e, 0.0, 0.001, "Entropia de buffer zerado deveria ser 0.0");
}

/**
 * Teste: buffer com alta entropia (dados pseudo-aleatorios)
 * 
 * Gerei um buffer com uma sequencia que parece aleatoria,
 * mas na verdade é deterministica (i * 13 + 7) % 256.
 * A entropia deve ficar proxima de 8.0 (maximo teorico)
 */
Test(entropy, high_entropy) {
    unsigned char buf[256];
    for (int i = 0; i < 256; i++) {
        buf[i] = (unsigned char)((i * 13 + 7) % 256);
    }
    double e = calculate_shannon_entropy(buf, 256);
    cr_assert_gt(e, 7.0, "Entropia de dados pseudo-aleatorios deveria ser > 7.0");
}

/**
 * Teste: string ASCII normal
 * 
 * Texto normal em ingles tem distribuicao de bytes bem irregular,
 * entao a entropia tende a ser baixa (entre 3 e 5).
 * Eu poderia ter usado um texto em portugues, mas optei por ingles
 * pq os caracteres sao todos ASCII padrao.
 */
Test(entropy, ascii_string) {
    const char *text = "This is a normal ASCII string with low entropy";
    double e = calculate_shannon_entropy((unsigned char*)text, strlen(text));
    cr_assert_lt(e, 5.0, "Entropia de texto ASCII deveria ser < 5.0");
    cr_assert_gt(e, 3.0, "Entropia de texto ASCII deveria ser > 3.0");
}

/**
 * Teste: buffer vazio (length = 0)
 * 
 * Esse é um caso de borda. Se o buffer ta vazio, nao tem o que calcular.
 * A funcao atual ja trata isso retornando 0.0.
 * Mantive assim pq nao vejo motivo pra mudar.
 */
Test(entropy, empty_buffer) {
    double e = calculate_shannon_entropy(NULL, 0);
    cr_assert_float_eq(e, 0.0, 0.001, "Entropia de buffer vazio deveria ser 0.0");
}

/**
 * Teste: buffer com um unico byte repetido
 * 
 * Se todos os bytes sao iguais (ex: tudo 'A'), a entropia deve ser 0.0
 * Isso é o mesmo caso do buffer zerado, mas com outro valor.
 */
Test(entropy, single_byte_repeated) {
    unsigned char buf[100];
    memset(buf, 'A', 100);
    double e = calculate_shannon_entropy(buf, 100);
    cr_assert_float_eq(e, 0.0, 0.001, "Entropia de bytes repetidos deveria ser 0.0");
}

/**
 * Teste: buffer com distribuicao uniforme (todos os 256 bytes uma vez)
 * 
 * Esse é o caso mais extremo: cada byte aparece exatamente uma vez.
 * A entropia deve ser exatamente 8.0 (log2(256) = 8)
 * Isso pq a probabilidade de cada byte é 1/256.
 */
Test(entropy, uniform_distribution) {
    unsigned char buf[256];
    for (int i = 0; i < 256; i++) {
        buf[i] = (unsigned char)i;
    }
    double e = calculate_shannon_entropy(buf, 256);
    cr_assert_float_eq(e, 8.0, 0.001, "Entropia de distribuicao uniforme deveria ser 8.0");
}