package br.com.auriga;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.DataLengthException;

public class RSFNArquivo {

    private byte[] arquivoAberto;
    private byte[] arquivoCifrado;
    private byte[] header;
    private byte[] payload;

    private int hdrTamanho;
    private int hdrVersao;
    private int hdrCodErro;
    private int hdrEspecial;
    private int hdrAlgAssimetricoDst;
    private int hdrAlgSimetrico;
    private int hdrAlgAssimetricoLocal;
    private int hdrAlgHash;
    private int hdrAcDestino;
    private String hdrNrSreDestino;
    private int hdrAcOrigem;
    private String hdrNrSreOrigem;
    private byte[] criptogramaChave;
    private byte[] assMensagem;

    public RSFNArquivo() {
        //Valores default
        hdrTamanho = 588;
        hdrVersao = 3;
        hdrCodErro = 0;
        hdrEspecial = 0;
        hdrAlgAssimetricoDst = 2;
        hdrAlgSimetrico = 2;
        hdrAlgAssimetricoLocal = 2;
        hdrAlgHash = 3;
        hdrAcDestino = 0;
        hdrNrSreDestino = StringUtils.leftPad("0", 32);
        hdrAcOrigem = 0;
        hdrNrSreOrigem = StringUtils.leftPad("0", 32);
        criptogramaChave = new byte[256];
        assMensagem = new byte[256];
    }

    public RSFNArquivo parseArquivoRSFN(byte[] arquivo) {

        ByteBuffer buffer = ByteBuffer.wrap(arquivo);

        hdrTamanho = buffer.getShort();
        hdrVersao = buffer.get();
        hdrCodErro = buffer.get();
        hdrEspecial = buffer.get();
        // Byte usado para tratamento futuro;
        buffer.get();
        hdrAlgAssimetricoDst = buffer.get();
        hdrAlgSimetrico = buffer.get();
        hdrAlgAssimetricoLocal = buffer.get();
        hdrAlgHash = buffer.get();
        hdrAcDestino = buffer.get();

        byte[] nrSreDestino = new byte[32];
        buffer.get(nrSreDestino);
        hdrNrSreDestino = new String(nrSreDestino);

        hdrAcOrigem = buffer.get();

        byte[] nrSreOrigem = new byte[32];
        buffer.get(nrSreOrigem);
        hdrNrSreOrigem = new String(nrSreOrigem);

        buffer.get(criptogramaChave);
        buffer.get(assMensagem);

        payload = new byte[buffer.remaining()];
        buffer.get(payload);

        return this;
    }

    public RSFNArquivo geraArquivoRSFN() {

        ByteBuffer buffer = ByteBuffer.allocate(hdrTamanho);

        //Concatenando o header
        buffer.putShort((short)hdrTamanho);
        buffer.put((byte)hdrVersao);
        buffer.put((byte)hdrCodErro);
        buffer.put((byte)hdrEspecial);
        // Byte usado para tratamento futuro;
        buffer.put((byte) 0);
        buffer.put((byte) hdrAlgAssimetricoDst);
        buffer.put((byte) hdrAlgSimetrico);
        buffer.put((byte) hdrAlgAssimetricoLocal);
        buffer.put((byte) hdrAlgHash);
        buffer.put((byte) hdrAcDestino);
        buffer.put(hdrNrSreDestino.getBytes());
        buffer.put((byte) hdrAcOrigem);
        buffer.put(hdrNrSreOrigem.getBytes());
        buffer.put(criptogramaChave);
        buffer.put(assMensagem);
        //Concatenando o payload
        buffer.put(payload);

        arquivoCifrado = buffer.array();

        return this;
    }

    public RSFNArquivo abreArquivo(PublicKey pbKey, PrivateKey prKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        arquivoAberto = CriptoRSFN.decifraArquivo(this, pbKey, prKey);
        return this;
    }

    public RSFNArquivo codificaArquivo(byte[] payloadAberto, PublicKey pbKey, PrivateKey prKey)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException, SignatureException, DataLengthException, IOException, CryptoException {
        CriptoRSFN.cifraArquivo(payloadAberto, this, pbKey, prKey);
        return this;
    }

    public byte[] getArquivoAberto() {
        return arquivoAberto;
    }

    public RSFNArquivo setArquivoAberto(byte[] arquivoAberto) {
        this.arquivoAberto = arquivoAberto;
        return this;
    }

    public byte[] getArquivoCifrado() {
        return arquivoCifrado;
    }

    public RSFNArquivo setArquivoCifrado(byte[] arquivoCifrado) {
        this.arquivoCifrado = arquivoCifrado;
        return this;
    }

    public byte[] getHeader() {
        return header;
    }

    public RSFNArquivo setHeader(byte[] header) {
        this.header = header;
        return this;
    }

    public byte[] getPayload() {
        return payload;
    }

    public RSFNArquivo setPayload(byte[] payload) {
        this.payload = payload;
        return this;
    }

    public int getHdrTamanho() {
        return hdrTamanho;
    }

    public RSFNArquivo setHdrTamanho(int hdrTamanho) {
        this.hdrTamanho = hdrTamanho;
        return this;
    }

    public int getHdrVersao() {
        return hdrVersao;
    }

    public RSFNArquivo setHdrVersao(int hdrVersao) {
        this.hdrVersao = hdrVersao;
        return this;
    }

    public int getHdrCodErro() {
        return hdrCodErro;
    }

    public RSFNArquivo setHdrCodErro(int hdrCodErro) {
        this.hdrCodErro = hdrCodErro;
        return this;
    }

    public int getHdrEspecial() {
        return hdrEspecial;
    }

    public RSFNArquivo setHdrEspecial(int hdrEspecial) {
        this.hdrEspecial = hdrEspecial;
        return this;
    }

    public int getHdrAlgAssimetricoDst() {
        return hdrAlgAssimetricoDst;
    }

    public RSFNArquivo setHdrAlgAssimetricoDst(int hdrAlgAssimetricoDst) {
        this.hdrAlgAssimetricoDst = hdrAlgAssimetricoDst;
        return this;
    }

    public int getHdrAlgSimetrico() {
        return hdrAlgSimetrico;
    }

    public RSFNArquivo setHdrAlgSimetrico(int hdrAlgSimetrico) {
        this.hdrAlgSimetrico = hdrAlgSimetrico;
        return this;
    }

    public int getHdrAlgAssimetricoLocal() {
        return hdrAlgAssimetricoLocal;
    }

    public RSFNArquivo setHdrAlgAssimetricoLocal(int hdrAlgAssimetricoLocal) {
        this.hdrAlgAssimetricoLocal = hdrAlgAssimetricoLocal;
        return this;
    }

    public int getHdrAlgHash() {
        return hdrAlgHash;
    }

    public RSFNArquivo setHdrAlgHash(int hdrAlgHash) {
        this.hdrAlgHash = hdrAlgHash;
        return this;
    }

    public int getHdrAcDestino() {
        return hdrAcDestino;
    }

    public RSFNArquivo setHdrAcDestino(int hdrAcDestino) {
        this.hdrAcDestino = hdrAcDestino;
        return this;
    }

    public String getHdrNrSreDestino() {
        return hdrNrSreDestino;
    }

    public RSFNArquivo setHdrNrSreDestino(String hdrNrSreDestino) {
        this.hdrNrSreDestino = hdrNrSreDestino;
        return this;
    }

    public int getHdrAcOrigem() {
        return hdrAcOrigem;
    }

    public RSFNArquivo setHdrAcOrigem(int hdrAcOrigem) {
        this.hdrAcOrigem = hdrAcOrigem;
        return this;
    }

    public String getHdrNrSreOrigem() {
        return hdrNrSreOrigem;
    }

    public RSFNArquivo setHdrNrSreOrigem(String hdrNrSreOrigem) {
        this.hdrNrSreOrigem = hdrNrSreOrigem;
        return this;
    }

    public byte[] getCriptogramaChave() {
        return criptogramaChave;
    }

    public RSFNArquivo setCriptogramaChave(byte[] criptogramaChave) {
        this.criptogramaChave = criptogramaChave;
        return this;
    }

    public byte[] getAssMensagem() {
        return assMensagem;
    }

    public RSFNArquivo setAssMensagem(byte[] assMensagem) {
        this.assMensagem = assMensagem;
        return this;
    }

    @Override
    public String toString() {
        return "RSFNArquivo [arquivoAberto=" + Arrays.toString(arquivoAberto) + ", arquivoCifrado="
                + Arrays.toString(arquivoCifrado) + ", assMensagem=" + Arrays.toString(assMensagem)
                + ", criptogramaChave=" + Arrays.toString(criptogramaChave) + ", hdrAcDestino=" + hdrAcDestino
                + ", hdrAcOrigem=" + hdrAcOrigem + ", hdrAlgAssimetricoDst=" + hdrAlgAssimetricoDst
                + ", hdrAlgAssimetricoLocal=" + hdrAlgAssimetricoLocal + ", hdrAlgHash=" + hdrAlgHash
                + ", hdrAlgSimetrico=" + hdrAlgSimetrico + ", hdrCodErro=" + hdrCodErro + ", hdrEspecial=" + hdrEspecial
                + ", hdrNrSreDestino=" + hdrNrSreDestino + ", hdrNrSreOrigem=" + hdrNrSreOrigem + ", hdrTamanho="
                + hdrTamanho + ", hdrVersao=" + hdrVersao + ", header=" + Arrays.toString(header) + ", payload="
                + Arrays.toString(payload) + "]";
    }

}
