package br.com.auriga;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

public class CriptoRSFN {

    public static byte[] decifraArquivo(RSFNArquivo rsfnArquivo, PublicKey pbKey,
            PrivateKey prKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        ParametroCriptoAES paramAES = decifraCriptograma(rsfnArquivo.getCriptogramaChave(), prKey);
        byte[] payloadAberto = decifraPayload(rsfnArquivo.getPayload(), paramAES);
        if (!confereAssinatura(payloadAberto, rsfnArquivo.getAssMensagem(), pbKey)) {
            throw new SecurityException("Assinatura nao confere");
        }
        return payloadAberto;
    }

    public static void cifraArquivo(byte[] payloadAberto, RSFNArquivo rsfnArquivo, PublicKey pbKey,
            PrivateKey prKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException, DataLengthException, IOException, CryptoException {
        ParametroCriptoAES paramAES = new ParametroCriptoAES();
        byte[] criptogramaChave = cifraCriptograma(paramAES, pbKey);
        byte[] assinaturaMensagem = assinaMensagem(payloadAberto, prKey);
        byte[] payloadCifrado = cifraPayload(payloadAberto, paramAES);
        rsfnArquivo.setCriptogramaChave(criptogramaChave);
        rsfnArquivo.setAssMensagem(assinaturaMensagem);
        rsfnArquivo.setPayload(payloadCifrado);
    }

    public static ParametroCriptoAES decifraCriptograma(byte[] criptograma, PrivateKey key)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return new ParametroCriptoAES(cipher.doFinal(criptograma));
    }

    public static byte[] cifraCriptograma(ParametroCriptoAES param, PublicKey key)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, SecureRandom.getInstance("DRBG"));
        return cipher.doFinal(param.criptograma);
    }

    public static byte[] decifraPayload(byte[] payload, ParametroCriptoAES parmAES) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, parmAES.chave, new GCMParameterSpec(128, parmAES.iv));
        return cipher.doFinal(payload);
    }

    public static byte[] cifraPayload(byte[] payload, ParametroCriptoAES parmAES) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, parmAES.chave, new GCMParameterSpec(128, parmAES.iv),
                SecureRandom.getInstance("DRBG"));
        return cipher.doFinal(payload);
    }

    public static boolean confereAssinatura(byte[] payloadAberto, byte[] assinatura, PublicKey pbKey)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, SignatureException {
        Signature sign = Signature.getInstance("SHA256WithRSA");
        sign.initVerify(pbKey);
        sign.update(payloadAberto);
        return sign.verify(assinatura);

    }

    public static byte[] assinaMensagem(byte[] payloadAberto, PrivateKey prKey)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, SignatureException, IOException, DataLengthException, CryptoException {
        
        AsymmetricKeyParameter param = PrivateKeyFactory.createKey(prKey.getEncoded());

        RSADigestSigner signer = new RSADigestSigner(new SHA256Digest());
        signer.init(true, param);
        signer.update(payloadAberto, 0, payloadAberto.length);
        return signer.generateSignature();
    }

}
