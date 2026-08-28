<div align="center">
  <img src="./imagem/banner.gif" alt="BinSecScan Banner" width="100%">
</div>

---

Muitos desenvolvedores acham que remover hardcoded secrets do código-fonte resolve o problema, mas esquecem que eles podem permanecer nas strings do binário compilado. Ferramentas como trufflehog focam em repositórios Git; poucas focam em artefatos de build de forma eficiente. Chaves de API, tokens JWT ou senhas deixadas em strings constantes dentro de executáveis ELF/PE viram um risco silencioso pós-compilação.

Então resolvi criar essa ferramenta em C que lê o cabeçalho de arquivos binários (ELF para Linux, PE para Windows, com suporte a macOS via CI), mapeia as seções de dados (`.rodata`, `.data`, `.rdata`, `.strtab`, `.dynstr` e `.text`) e aplica heurísticas de entropia (Shannon Entropy) para detectar strings com alta aleatoriedade – um forte indicativo de chaves criptográficas, tokens ou dados ofuscados.

- Baixo uso de memória (usa `mmap` para acesso eficiente ao arquivo).
- Detecção baseada em entropia matemática, não apenas regex, reduzindo falsos positivos.
- Integração direta como step em um Dockerfile ou GitHub Action.
- Testes unitários com Criterion e pipeline CI/CD que compila e testa em Linux, Windows e macOS.
- Makefile para compilação simples e instalação no sistema.
- Licença MIT e documentação completa.

**Stack:** C puro, manipulação de file descriptors, algoritmos de cálculo de entropia.

Scanners de container são pesados e lentos. **BinSecScan** foi projetado para ser leve, rápido e integrado diretamente ao pipeline de build, validando o binário antes do deploy.
