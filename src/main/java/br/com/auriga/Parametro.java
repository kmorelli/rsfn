package br.com.auriga;

import org.apache.commons.cli.Option;

public enum Parametro {
    CIFRA( Option.builder("cifra").desc("Cifrar um arquivo RSFN").build()),
    DECIFRA( Option.builder("decifra").desc("Decifrar um arquivo RSFN").build()),
    ARQUIVO(Option.builder("in").hasArg().argName("Arquivo de Entrada").desc("Arquivo a ser processado. Se deseja cifrar, deve informar o arquivo em claro, se deseja decifrar, o arquivo cifrado").build()),
    PRKEY(Option.builder("privkey").hasArg().argName("Chave Privada").desc("Chave privada de quem vai tratar o arquivo no formato PKCS8 PEM").build()),
    PBKEY(Option.builder("pbkey").hasArg().argName("Chave Publica").desc("Chave publica de quem esta se comunicando, no formato PKCS8 PEM").build()),
    ACORIGEM(Option.builder("acogm").hasArg().argName("Codigo AC Origem").desc("Codigo da AC do certificado de origem, de 1 a 6").build()),
    ACDESTINO(Option.builder("acdst").hasArg().argName("Codigo AC Destino").desc("Codigo da AC do certificado de destino, de 1 a 6").build()),
    NRSREORIGEM(Option.builder("nrsreogm").hasArg().argName("Numero de Serie Origem").desc("Numero de Serie do certificado de origem, ate 16 posicoes").build()),
    NRSREESTINO(Option.builder("nrsredst").hasArg().argName("Numero de Serie Destino").desc("Numero de Serie do certificado de destino, ate 16 posicoes").build());

    private Option option;

    Parametro(Option option) {
        this.option = option;
    }

    public Option getOption() {
        return option;
    }
}
