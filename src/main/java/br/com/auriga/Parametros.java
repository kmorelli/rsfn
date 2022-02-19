package br.com.auriga;

import java.io.File;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.regex.Pattern;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

public class Parametros {

    final private static Pattern REGEX_HEX = Pattern.compile("^\\p{XDigit}+$");

    final private CommandLine cmd;

    public Parametros(CommandLine cmd) {
        this.cmd = cmd;
    }

    protected String leParametro(Option option, boolean obrigatorio) throws IOException {
        if (!cmd.hasOption(option)) {
            if (obrigatorio) {
                throw new IllegalArgumentException("Deve ser informado o parametro " + option.getArgName());
            }
            return null;
        }
        return cmd.getOptionValue(option);
    }

    protected int leParametroNumerico(Option option, boolean obrigatorio) throws IOException {
        String valorTexto = leParametro(option, obrigatorio);
        if (valorTexto == null) {
            return 0;
        }
        int valor = Integer.parseInt(valorTexto);
        return valor;
    }

    protected byte[] leParametroArquivo(Option option, boolean obrigatorio) throws IOException {
        final String nomeArquivo = leParametro(option, obrigatorio);
        if (nomeArquivo == null) {
            return null;
        }
        final File file = FileUtils.getFile(nomeArquivo);
        return FileUtils.readFileToByteArray(file);
    }

    protected boolean isACValida(int numAc) {
        if (numAc > 0 && numAc <= 6) {
            return true;
        }
        return false;
    }

    protected String formataNrSre(String nrSre) throws IllegalArgumentException {
        if (nrSre.length() > 16) {
            throw new IllegalArgumentException("Numero de serie e maior que 16 bytes");
        }
        if (!REGEX_HEX.matcher(nrSre).matches()) {
            throw new IllegalArgumentException("Numero de serie nao e hexadecimal");
        }
        String formatado = StringUtils.leftPad(nrSre, 16, "0").toUpperCase();
        return Hex.encodeHexString(formatado.getBytes(), false);
    }

    protected PrivateKey obtemChavePrivada(byte[] chave) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String pem = new String(chave);
        String pemLimpo = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] der = Base64.decodeBase64(pemLimpo);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec pkcs8key = new PKCS8EncodedKeySpec(der);
        return kf.generatePrivate(pkcs8key);
    }

    protected PublicKey obtemChavePublica(byte[] chave) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String pem = new String(chave);
        String pemLimpo = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] der = Base64.decodeBase64(pemLimpo);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec pkcs8key = new X509EncodedKeySpec(der);
        return kf.generatePublic(pkcs8key);
    }
}
