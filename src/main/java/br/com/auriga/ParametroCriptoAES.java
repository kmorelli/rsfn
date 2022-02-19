package br.com.auriga;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ParametroCriptoAES {
    public byte[] iv;
    public SecretKey chave;
    public byte[] criptograma;

    public ParametroCriptoAES(byte[] criptograma) {
        this.criptograma = criptograma;
        ByteBuffer buffer = ByteBuffer.wrap(criptograma);
        
        byte[] chaveByte = new byte[32];
        buffer.get(chaveByte);
        chave = new SecretKeySpec(chaveByte, "AES");
        
        iv = new byte[12];
        buffer.get(iv);
    }

    public ParametroCriptoAES() throws NoSuchAlgorithmException {
        SecureRandom rand = SecureRandom.getInstance("DRBG");
        iv = new byte[12];
        rand.nextBytes(iv);
        
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256, rand);
        chave = keyGen.generateKey();
        
        ByteBuffer buffer = ByteBuffer.allocate(44);
        buffer.put(chave.getEncoded());
        buffer.put(iv);

        criptograma = buffer.array();
    }
}
