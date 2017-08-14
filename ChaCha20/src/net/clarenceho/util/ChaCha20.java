package net.clarenceho.util;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/*
 * Quick-n-dirty standalone implementation of ChaCha 256-bit
 * <p/>
 * Created by Clarence Ho on 20150729
 * <p/>
 * References:
 * ~ http://cr.yp.to/chacha/chacha-20080128.pdf
 * ~ https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01
 * ~ https://github.com/quartzjer/chacha20
 * ~ https://github.com/jotcmd/chacha20
 */
public class ChaCha20 {
    
    /*
     * Key size in byte
     */
    public static final int KEY_SIZE = 32;

    /*
     * Nonce size in byte (reference implementation)
     */
    public static final int NONCE_SIZE_REF = 8;

    /*
     * Nonce size in byte (IETF draft)
     */
    public static final int NONCE_SIZE_IETF = 12;

    /*
     * Sigma ints
     */
    public static final int[] SIGMA = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    /*
     * Block size
     */
    public static final int BLOCK_SIZE = 64;

    /*
     * Rounds (must be a multiple of 2)
     */
    public static final int ROUNDS = 20;

    private int[] initMatrix, matrix = new int[16];
    private int lastBlock = BLOCK_SIZE;

    private ChaCha20(byte[] key, byte[] nonce, int counter) {
        init(key, nonce, counter);
    }

    /* Init methods */

    private void init(byte[] key, byte[] nonce, int counter) {
        if (key.length != KEY_SIZE)
            throw new IllegalArgumentException("Invalid key size. Current: " + key.length + ", expected: " + KEY_SIZE);

        System.arraycopy(SIGMA, 0, matrix, 0, SIGMA.length);

        initKey(key);
        initNonce(nonce, counter);

        initMatrix = matrix.clone();
    }

    private void initKey(byte[] key) {
        matrix[4] = littleEndianToInt(key, 0);
        matrix[5] = littleEndianToInt(key, 4);
        matrix[6] = littleEndianToInt(key, 8);
        matrix[7] = littleEndianToInt(key, 12);
        matrix[8] = littleEndianToInt(key, 16);
        matrix[9] = littleEndianToInt(key, 20);
        matrix[10] = littleEndianToInt(key, 24);
        matrix[11] = littleEndianToInt(key, 28);
    }

    private void initNonce(byte[] nonce, int counter) {
        if (nonce.length == NONCE_SIZE_REF) {
            this.matrix[12] = 0;
            this.matrix[13] = 0;
            this.matrix[14] = littleEndianToInt(nonce, 0);
            this.matrix[15] = littleEndianToInt(nonce, 4);
        } else if (nonce.length == NONCE_SIZE_IETF) {
            this.matrix[12] = counter;
            this.matrix[13] = littleEndianToInt(nonce, 0);
            this.matrix[14] = littleEndianToInt(nonce, 4);
            this.matrix[15] = littleEndianToInt(nonce, 8);
        } else
            throw new IllegalArgumentException("Invalid nonce size. Current: " + nonce.length
                    + "expected: " + NONCE_SIZE_REF + " or " + NONCE_SIZE_IETF);
    }

    /* Encrypt/Decrypt methods */

    public void encrypt(byte[] dst, byte[] src, int len) {
        if (lastBlock != BLOCK_SIZE)
            throw new IllegalArgumentException("Last size isn't " + BLOCK_SIZE); //As it's a streamcipher

        dst = dst == null ? new byte[src.length] : dst;
        lastBlock = src.length;

        final int[] x = new int[16];
        final byte[] output = new byte[BLOCK_SIZE];
        int i, dpos = 0, spos = 0;

        while (len > 0) {
            System.arraycopy(matrix, 0, x, 0, matrix.length);

            for (i = ROUNDS; i > 0; i -= 2) {
                quarterRound(x, 0, 4, 8, 12);
                quarterRound(x, 1, 5, 9, 13);
                quarterRound(x, 2, 6, 10, 14);
                quarterRound(x, 3, 7, 11, 15);

                quarterRound(x, 0, 5, 10, 15);
                quarterRound(x, 1, 6, 11, 12);
                quarterRound(x, 2, 7, 8, 13);
                quarterRound(x, 3, 4, 9, 14);
            }

            for (i = 16; i-- > 0;) x[i] += this.matrix[i];
            for (i = 16; i-- > 0;) intToLittleEndian(x[i], output, 4 * i);

            this.matrix[12] += 1;
            if (this.matrix[12] <= 0)
                this.matrix[13] += 1;

            for (i = (len <= BLOCK_SIZE ? len : BLOCK_SIZE); i-- > 0;)
                dst[i + dpos] = (byte) (src[i + spos] ^ output[i]);

            if (len <= BLOCK_SIZE) return;

            len -= BLOCK_SIZE;
            spos += BLOCK_SIZE;
            dpos += BLOCK_SIZE;
        }

    }

    public void decrypt(byte[] dst, byte[] src, int len) {
        encrypt(dst, src, len);
    }

    /* int/byte conversation */

    protected int littleEndianToInt(byte[] bs, int i) {
        return (bs[i] & 0xff) | ((bs[i + 1] & 0xff) << 8) | ((bs[i + 2] & 0xff) << 16) | ((bs[i + 3] & 0xff) << 24);
    }

    private void intToLittleEndian(int n, byte[] bs, int off) {
        bs[off] = (byte) (n);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 24);
    }

    /* Rotate */

    private int rotate(int v, int c) {
        return (v << c) | (v >>> (32 - c));
    }

    private void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = rotate(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = rotate(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = rotate(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = rotate(x[b] ^ x[c], 7);
    }

    /* Reset method */

    public void reset() {
        matrix = initMatrix;
        lastBlock = BLOCK_SIZE;
    }

    /* Factory methods */

    public static ChaCha20 of(final String key, final String nonce) {
        return of(key.getBytes(StandardCharsets.US_ASCII), nonce.getBytes(StandardCharsets.US_ASCII), 0);
    }

    public static ChaCha20 of(final String key, final String nonce, final int counter) {
        return of(key.getBytes(StandardCharsets.US_ASCII), nonce.getBytes(StandardCharsets.US_ASCII), counter);
    }

    public static ChaCha20 of(final byte[] key, final byte[] nonce) {
        return new ChaCha20(key, nonce, 0);
    }

    public static ChaCha20 of(final byte[] key, final byte[] nonce, final int counter) {
        return new ChaCha20(key, nonce, counter);
    }

}
