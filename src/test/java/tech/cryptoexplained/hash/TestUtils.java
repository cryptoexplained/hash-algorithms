package tech.cryptoexplained.hash;

public class TestUtils {

    private TestUtils() {
    }

    public static byte[] toByteArray(int[] input) {
        byte[] output = new byte[input.length];
        for(int i = 0; i < input.length; i++) {
            output[i] = (byte) (input[i] & 0xff);
        }
        return output;
    }
}
