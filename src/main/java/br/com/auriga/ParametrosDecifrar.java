package br.com.auriga;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

public class ParametrosDecifrar extends Parametros {

    private byte[] arquivoEntrada;
    private PublicKey chavePublica;
    private PrivateKey chavePrivada;

    public ParametrosDecifrar(CommandLine cmd) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        super(cmd);

        arquivoEntrada = leParametroArquivo(Parametro.ARQUIVO.getOption(), true);

        byte[] bytePb = leParametroArquivo(Parametro.PBKEY.getOption(), true);
        chavePublica = obtemChavePublica(bytePb);

        byte[] bytePr = leParametroArquivo(Parametro.PRKEY.getOption(), true);
        chavePrivada = obtemChavePrivada(bytePr);

    }

    public byte[] getArquivoEntrada() {
        return arquivoEntrada;
    }

    public PublicKey getChavePublica() {
        return chavePublica;
    }

    public PrivateKey getChavePrivada() {
        return chavePrivada;
    }

    @Override
    public String toString() {
        return "ParametrosDecifrar [arquivoEntrada=" + Arrays.toString(arquivoEntrada) + ", chavePrivada="
                + Arrays.toString(chavePrivada.getEncoded()) + ", chavePublica=" + Arrays.toString(chavePublica.getEncoded()) + "]";
    }    
    
    
}
