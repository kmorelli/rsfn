package br.com.auriga;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.apache.commons.cli.CommandLine;

public class ParametrosCifrar extends Parametros {

    private byte[] arquivoEntrada;
    private PublicKey chavePublica;
    private PrivateKey chavePrivada;
    private int acOrigem;
    private String nrSreOrigem;
    private int acDestino;
    private String nrSreDestino;

    public ParametrosCifrar(CommandLine cmd) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        super(cmd);
    
        arquivoEntrada = leParametroArquivo(Parametro.ARQUIVO.getOption(), true);

        byte[] bytePb = leParametroArquivo(Parametro.PBKEY.getOption(), true);
        chavePublica = obtemChavePublica(bytePb);

        byte[] bytePr = leParametroArquivo(Parametro.PRKEY.getOption(), true);
        chavePrivada = obtemChavePrivada(bytePr);

        acOrigem = leParametroNumerico(Parametro.ACORIGEM.getOption(), true);
        if (!isACValida(acOrigem)) {
            throw new IllegalArgumentException("AC de origem nao e valida");
        }
        nrSreOrigem = formataNrSre(leParametro(Parametro.NRSREORIGEM.getOption(), true));

        acDestino = leParametroNumerico(Parametro.ACDESTINO.getOption(), true);
        if (!isACValida(acOrigem)) {
            throw new IllegalArgumentException("AC de destino nao e valida");
        }
        nrSreDestino = formataNrSre(leParametro(Parametro.NRSREESTINO.getOption(), true));
    
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

    public int getAcOrigem() {
        return acOrigem;
    }

    public String getNrSreOrigem() {
        return nrSreOrigem;
    }

    public int getAcDestino() {
        return acDestino;
    }

    public String getNrSreDestino() {
        return nrSreDestino;
    }

    @Override
    public String toString() {
        return "ParametrosCifrar [acDestino=" + acDestino + ", acOrigem=" + acOrigem + ", arquivoEntrada="
                + Arrays.toString(arquivoEntrada) + ", chavePrivada=" + Arrays.toString(chavePrivada.getEncoded())
                + ", chavePublica=" + Arrays.toString(chavePublica.getEncoded()) + ", nrSreDestino=" + nrSreDestino
                + ", nrSreOrigem=" + nrSreOrigem + "]";
    }
    
}
