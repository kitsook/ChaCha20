package net.clarenceho.util;

import static org.junit.Assert.*;
import org.junit.Test;

import java.util.Arrays;
import java.util.Random;
import java.util.stream.IntStream;

// compare against Bouncy Castle's implementation
import org.bouncycastle.crypto.engines.ChaChaEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.StreamCipher;

/*
 * Test cases for standalone implementation of ChaCha 256-bit
 * <p/>
 * Created by Clarence Ho on 20150729
 */
public class TestChaCha20 {

    /*
     * Test vectors from IETF draft
     * https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01
     */
    final byte[][] IETF_KEY = {
            hexStr2Byte("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            hexStr2Byte("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            new byte[32],
            hexStr2Byte("0000000000000000000000000000000000000000000000000000000000000001"),
            hexStr2Byte("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
    };
    final byte[][] IETF_NONCE = {
            hexStr2Byte("000000090000004a00000000"),
            hexStr2Byte("000000000000004a00000000"),
            new byte[12],
            hexStr2Byte("000000000000000000000002"),
            hexStr2Byte("000000000000000000000002")
    };
    final byte[][] IETF_PLAIN = {
            new byte[64],
            hexStr2Byte(
                    "4c616469657320616e642047656e746c" +
                    "656d656e206f662074686520636c6173" +
                    "73206f66202739393a20496620492063" +
                    "6f756c64206f6666657220796f75206f" +
                    "6e6c79206f6e652074697020666f7220" +
                    "746865206675747572652c2073756e73" +
                    "637265656e20776f756c642062652069" +
                    "742e"
                    ),
            new byte[64],
            hexStr2Byte(
                    "416e79207375626d697373696f6e2074" +
                    "6f20746865204945544620696e74656e" +
                    "6465642062792074686520436f6e7472" +
                    "696275746f7220666f72207075626c69" +
                    "636174696f6e20617320616c6c206f72" +
                    "2070617274206f6620616e2049455446" +
                    "20496e7465726e65742d447261667420" +
                    "6f722052464320616e6420616e792073" +
                    "746174656d656e74206d616465207769" +
                    "7468696e2074686520636f6e74657874" +
                    "206f6620616e20494554462061637469" +
                    "7669747920697320636f6e7369646572" +
                    "656420616e20224945544620436f6e74" +
                    "7269627574696f6e222e205375636820" +
                    "73746174656d656e747320696e636c75" +
                    "6465206f72616c2073746174656d656e" +
                    "747320696e2049455446207365737369" +
                    "6f6e732c2061732077656c6c20617320" +
                    "7772697474656e20616e6420656c6563" +
                    "74726f6e696320636f6d6d756e696361" +
                    "74696f6e73206d61646520617420616e" +
                    "792074696d65206f7220706c6163652c" +
                    "20776869636820617265206164647265" +
                    "7373656420746f"
                    ),
            hexStr2Byte(
                    "2754776173206272696c6c69672c2061" +
                    "6e642074686520736c6974687920746f" +
                    "7665730a446964206779726520616e64" +
                    "2067696d626c6520696e207468652077" +
                    "6162653a0a416c6c206d696d73792077" +
                    "6572652074686520626f726f676f7665" +
                    "732c0a416e6420746865206d6f6d6520" +
                    "7261746873206f757467726162652e"
                    )
    };
    final byte[][] IETF_EXPECTED = {
            hexStr2Byte(
                    "10f1e7e4d13b5915500fdd1fa32071c4" +
                    "c7d1f4c733c068030422aa9ac3d46c4e" +
                    "d2826446079faa0914c2d705d98b02a2" +
                    "b5129cd1de164eb9cbd083e8a2503c4e"
                    ),
            hexStr2Byte(
                    "6e2e359a2568f98041ba0728dd0d6981" +
                    "e97e7aec1d4360c20a27afccfd9fae0b" +
                    "f91b65c5524733ab8f593dabcd62b357" +
                    "1639d624e65152ab8f530c359f0861d8" +
                    "07ca0dbf500d6a6156a38e088a22b65e" +
                    "52bc514d16ccf806818ce91ab7793736" +
                    "5af90bbf74a35be6b40b8eedf2785e42" +
                    "874d"
                    ),
            hexStr2Byte(
                    "76b8e0ada0f13d90405d6ae55386bd28" +
                    "bdd219b8a08ded1aa836efcc8b770dc7" +
                    "da41597c5157488d7724e03fb8d84a37" +
                    "6a43b8f41518a11cc387b669b2ee6586"
                    ),
            hexStr2Byte(
                    "a3fbf07df3fa2fde4f376ca23e827370" +
                    "41605d9f4f4f57bd8cff2c1d4b7955ec" +
                    "2a97948bd3722915c8f3d337f7d37005" +
                    "0e9e96d647b7c39f56e031ca5eb6250d" +
                    "4042e02785ececfa4b4bb5e8ead0440e" +
                    "20b6e8db09d881a7c6132f420e527950" +
                    "42bdfa7773d8a9051447b3291ce1411c" +
                    "680465552aa6c405b7764d5e87bea85a" +
                    "d00f8449ed8f72d0d662ab052691ca66" +
                    "424bc86d2df80ea41f43abf937d3259d" +
                    "c4b2d0dfb48a6c9139ddd7f76966e928" +
                    "e635553ba76c5c879d7b35d49eb2e62b" +
                    "0871cdac638939e25e8a1e0ef9d5280f" +
                    "a8ca328b351c3c765989cbcf3daa8b6c" +
                    "cc3aaf9f3979c92b3720fc88dc95ed84" +
                    "a1be059c6499b9fda236e7e818b04b0b" +
                    "c39c1e876b193bfe5569753f88128cc0" +
                    "8aaa9b63d1a16f80ef2554d7189c411f" +
                    "5869ca52c5b83fa36ff216b9c1d30062" +
                    "bebcfd2dc5bce0911934fda79a86f6e6" +
                    "98ced759c3ff9b6477338f3da4f9cd85" +
                    "14ea9982ccafb341b2384dd902f3d1ab" +
                    "7ac61dd29c6f21ba5b862f3730e37cfd" +
                    "c4fd806c22f221"
                    ),
            hexStr2Byte(
                    "62e6347f95ed87a45ffae7426f27a1df" +
                    "5fb69110044c0d73118effa95b01e5cf" +
                    "166d3df2d721caf9b21e5fb14c616871" +
                    "fd84c54f9d65b283196c7fe4f60553eb" +
                    "f39c6402c42234e32a356b3e764312a6" +
                    "1a5532055716ead6962568f87d3f3f77" +
                    "04c6a8d1bcd1bf4d50d6154b6da731b1" +
                    "87b58dfd728afa36757a797ac188d1"
                    )

    };
    final int[] IETF_COUNTER = { 1, 1, 0, 1, 42 };

    protected byte[] testImplementation(byte[] plain, byte[] key, byte[] nonce, int counter) {
        byte[] result = new byte[plain.length];
        try {
            ChaCha20 cipher = new ChaCha20(key, nonce, counter);

            cipher.encrypt(result, plain, plain.length);

        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
        return result;
    }

    @Test
    public void testIetfVector() {
        IntStream.range(0, IETF_KEY.length).parallel().forEach(l ->
                assertTrue(Arrays.equals(testImplementation(IETF_PLAIN[l], IETF_KEY[l], IETF_NONCE[l], IETF_COUNTER[l]),
                                         IETF_EXPECTED[l])));
    }

    /*
     * Random tests of different length
     */
    @Test
    public void testRandom1() {
        int[] len = {16, 32, 64, 128, 100, 200, 256, 300, 500, 512, 1024, 1048576, 100 * 1048576};
        IntStream.of(len).parallel().forEach(l -> assertTrue(testRandomLen(l)));
    }

    /*
     * Random tests with huge amount of data
     */
    /*
    @Test
    public void testBig() {
        int[] len = {Integer.MAX_VALUE-10};
        IntStream.of(len).parallel().forEach(l -> assertTrue(testRandomBC(l)));
    }
     */

    protected boolean testRandomLen(int len) {
        Random rand = new Random();

        byte[] key = new byte[ChaCha20.KEY_SIZE];
        rand.nextBytes(key);
        byte[] nonce = new byte[ChaCha20.NONCE_SIZE_IETF];
        rand.nextBytes(nonce);
        byte[] plain = new byte[len];
        rand.nextBytes(plain);
        int counter = 1;

        byte[] encrypted = testImplementation(plain, key, nonce, counter);
        byte[] decrypted = testImplementation(encrypted, key, nonce, counter);

        return Arrays.equals(plain, decrypted);
    }

    /*
     * Random tests against Bouncy Castle
     */
    @Test
    public void testRandom2() {
        int[] len = {16, 32, 64, 128, 100, 200, 256, 300, 500, 512, 1024, 1048576, 100 * 1048576};
        IntStream.of(len).parallel().forEach(l -> assertTrue(testRandomBC(l)));
    }

    protected boolean testRandomBC(int len) {
        Random rand = new Random();

        byte[] key = new byte[ChaCha20.KEY_SIZE];
        rand.nextBytes(key);
        byte[] nonce = new byte[ChaCha20.NONCE_SIZE_REF];
        rand.nextBytes(nonce);
        byte[] plain = new byte[len];
        rand.nextBytes(plain);
        int counter = 0;

        byte[] bc = bouncyCastle(plain, key, nonce);
        byte[] own = testImplementation(plain, key, nonce, counter);

        return Arrays.equals(own, bc);
    }

    @Test
    public void testBC1() {
        byte[] key = hexStr2Byte("0000000000000000000000000000000000000000000000000000000000000000");
        byte[] nonce = hexStr2Byte("0000000000000000");
        int counter = 0;

        byte[] zeroes = hexStr2Byte(
                "00000000000000000000000000000000"
              + "00000000000000000000000000000000"
              + "00000000000000000000000000000000"
              + "00000000000000000000000000000000");

        byte[] own = testImplementation(zeroes, key, nonce, counter);
        byte[] bc = bouncyCastle(zeroes, key, nonce);

        assertTrue(Arrays.equals(own, bc));
    }

    /*
     * Invoke Bouncy Castle's implementation of ChaCha
     */
    protected byte[] bouncyCastle(byte[] plain, byte[] key, byte[] nonce) {
        StreamCipher chaCha = new ChaChaEngine(20);
        chaCha.init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] buf = new byte[plain.length];
        chaCha.processBytes(plain, 0, plain.length, buf, 0);
        return buf;
    }


    /*
     * Test vector from IETF draft
     * https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01
     */
    @Test
    public void testQuarterRound1() {
        int buf[] = {0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567};
        int expected[] = {0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb};

        ChaCha20.quarterRound(buf, 0, 1, 2, 3);
        assertTrue(Arrays.equals(buf, expected));
    }


    /*
     * Test vector from IETF draft
     * https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01
     */
    @Test
    public void testQuarterRound2() {
        int buf[] = {
                0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
                0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
                0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
                0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
        };
        int expected[] = {
            0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
            0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
            0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
            0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
        };

        ChaCha20.quarterRound(buf, 2, 7, 8, 13);
        assertTrue(Arrays.equals(buf, expected));
    }

    private byte[] hexStr2Byte(String hexStr) {
        int len = hexStr.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexStr.charAt(i), 16) << 4)
                                 + Character.digit(hexStr.charAt(i+1), 16));
        }
        return data;
    }

    final protected static char[] hexArray = "0123456789abcdef".toCharArray();
    private String byte2HexStr(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
