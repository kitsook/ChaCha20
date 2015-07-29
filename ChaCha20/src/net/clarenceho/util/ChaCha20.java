package net.clarenceho.util;

/*
 * References:
 * ~ http://cr.yp.to/chacha/chacha-20080128.pdf
 * ~ https://github.com/quartzjer/chacha20
 * ~ https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01
 * ~ https://github.com/jotcmd/chacha20/blob/master/Chacha20.java
 * ~ https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/crypto/engines/ChaChaEngine.java
 * ~ https://github.com/codahale/chacha20/blob/master/chacha20.go
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

    private int[] matrix = new int[16];
    
    private int byte2Int_LE(byte[] x, int i) {
        return x[i] | (x[i + 1] << 8) | (x[i + 2] << 16) | (x[i + 3] << 24);
    }

    private void int2Byte_LE(int[] x, int i, int u) {
        x[i] = u;
        u >>>= 8;
        x[i + 1] = u;
        u >>>= 8;
        x[i + 2] = u;
        u >>>= 8;
        x[i + 3] = u;
    }

    protected static int ROTATE(int v, int c) {
        return (v << c) | (v >>> (32 - c));
    }
    
    protected static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = ROTATE(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = ROTATE(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = ROTATE(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = ROTATE(x[b] ^ x[c], 7);
    }
    
    public class WrongNonceSizeException extends Exception {
        private static final long serialVersionUID = 2687731889587117531L;
    }
    
    public class WrongKeySizeException extends Exception {
        private static final long serialVersionUID = -290509589749955895L;
    }

    
    public ChaCha20(byte[] key, byte[] nonce, int counter)
            throws WrongKeySizeException, WrongNonceSizeException {

        if (key.length != KEY_SIZE) {
            throw new WrongKeySizeException();
        }
        
        this.matrix[ 0] = 0x61707865;
        this.matrix[ 1] = 0x3320646e;
        this.matrix[ 2] = 0x79622d32;
        this.matrix[ 3] = 0x6b206574;
        this.matrix[ 4] = byte2Int_LE(key, 0);
        this.matrix[ 5] = byte2Int_LE(key, 4);
        this.matrix[ 6] = byte2Int_LE(key, 8);
        this.matrix[ 7] = byte2Int_LE(key, 12);
        this.matrix[ 8] = byte2Int_LE(key, 16);
        this.matrix[ 9] = byte2Int_LE(key, 20);
        this.matrix[10] = byte2Int_LE(key, 24);
        this.matrix[11] = byte2Int_LE(key, 28);
        
        if (nonce.length == NONCE_SIZE_REF) {        // reference implementation
            this.matrix[12] = 0;
            this.matrix[13] = 0;
            this.matrix[14] = byte2Int_LE(nonce, 0);
            this.matrix[15] = byte2Int_LE(nonce, 4);

        } else if (nonce.length == NONCE_SIZE_IETF) {
            this.matrix[12] = counter;
            this.matrix[13] = byte2Int_LE(nonce, 0);
            this.matrix[14] = byte2Int_LE(nonce, 4);
            this.matrix[15] = byte2Int_LE(nonce, 8);
        } else {
            throw new WrongNonceSizeException();
        }
    }
    
    public void encrypt(byte[] dst, byte[] src, int len) {
        int[] x = new int[16];
        int[] output = new int[64];
        int i, dpos = 0, spos = 0;

        while (len > 0) {
            for (i = 16; i-- > 0; ) x[i] = this.matrix[i];
            for (i = 20; i > 0; i -= 2) {
                quarterRound(x, 0, 4,  8, 12);
                quarterRound(x, 1, 5,  9, 13);
                quarterRound(x, 2, 6, 10, 14);
                quarterRound(x, 3, 7, 11, 15);
                quarterRound(x, 0, 5, 10, 15);
                quarterRound(x, 1, 6, 11, 12);
                quarterRound(x, 2, 7,  8, 13);
                quarterRound(x, 3, 4,  9, 14);
            }
            for (i = 16; i-- > 0; ) x[i] += this.matrix[i];
            for (i = 16; i-- > 0; ) int2Byte_LE(output, 4 * i, x[i]);

            this.matrix[12] += 1;
            if (this.matrix[12] <= 0) {
                this.matrix[13] += 1;
            }
            if (len <= 64) {
                for (i = len; i-- > 0; ) {
                    dst[i + dpos] = (byte) (src[i + spos] ^ output[i]);
                }
                return;
            }
            for (i = 64; i-- > 0; ) {
                dst[i + dpos] = (byte) (src[i + spos] ^ output[i]);
            }
            len -= 64;
            spos += 64;
            dpos += 64;
        }
    }
    
    public void decrypt(byte[] dst, byte[] src, int len) {
        encrypt(dst, src, len);
    }

}
