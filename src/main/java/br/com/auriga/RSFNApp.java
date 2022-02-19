package br.com.auriga;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;

public class RSFNApp {

    final public static String CIFRA = "CIFRA";
    final public static String DECIFRA = "DECIFRA";

    final public static String ARQUIVO_SAIDA = "outputRSFN.txt";

    final private CommandLine cmd;

    public RSFNApp(CommandLine cmd) {
        this.cmd = cmd;
    }

    public void inicia() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            SignatureException, DataLengthException, CryptoException {

        if (cmd.hasOption(Parametro.CIFRA.getOption())) {
            cifrar();
        }

        if (cmd.hasOption(Parametro.DECIFRA.getOption())) {
            decifrar();
        }
    }

    private void cifrar() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException, DataLengthException, CryptoException {
        ParametrosCifrar cifrar = new ParametrosCifrar(cmd);
        RSFNArquivo rsfnArquivo = new RSFNArquivo();
        rsfnArquivo.setHdrAcDestino(cifrar.getAcDestino())
        .setHdrNrSreDestino(cifrar.getNrSreDestino())
        .setHdrAcOrigem(cifrar.getAcOrigem())
        .setHdrNrSreOrigem(cifrar.getNrSreOrigem())
        .codificaArquivo(cifrar.getArquivoEntrada(), cifrar.getChavePublica(), cifrar.getChavePrivada())
        .geraArquivoRSFN();
        escreveArquivoSaida(rsfnArquivo.getArquivoCifrado());        
    }

    private void decifrar() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
            SignatureException {
        ParametrosDecifrar decifrar = new ParametrosDecifrar(cmd);
        RSFNArquivo rsfnArquivo = new RSFNArquivo();
        rsfnArquivo.parseArquivoRSFN(decifrar.getArquivoEntrada())
                .abreArquivo(decifrar.getChavePublica(), decifrar.getChavePrivada());
        escreveArquivoSaida(rsfnArquivo.getArquivoAberto());
        }

    private void escreveArquivoSaida(byte[] arquivo) throws IOException {
        //Escrevera a saida em um arquivo padrao
        File arquivoSaida = new File(ARQUIVO_SAIDA);
        FileUtils.touch(arquivoSaida);
        FileUtils.writeByteArrayToFile(arquivoSaida, arquivo);
    }

}