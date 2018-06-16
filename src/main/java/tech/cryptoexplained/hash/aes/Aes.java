package tech.cryptoexplained.hash.aes;

import com.sun.istack.internal.NotNull;
import tech.cryptoexplained.hash.common.HashDirection;

public class Aes {

    /**
     * Expand round keys
     *
     * @param inputKey     input key
     * @param roundsNumber number of AES rounds
     * @param direction    encryption or decryption direction
     * @return 128 bits round keys as integer array int[roundNumber][4]
     */
    public byte[] expandRoundKeys(@NotNull byte[] inputKey, int roundsNumber, @NotNull HashDirection direction) {
        AesKeyParam aesKeyParams = AesKeyParam.fromInputKey(inputKey);
        byte[] expandedKeys = new byte[roundsNumber * 16];
        System.arraycopy(inputKey, 0, expandedKeys, 0, inputKey.length);
        int iteration = 1;
        int bytesGenerated = aesKeyParams.getLengthBytes();
        while (bytesGenerated < expandedKeys.length) {
            generateNextBytes(expandedKeys, aesKeyParams, iteration, direction);
            bytesGenerated += aesKeyParams.getLengthBytes();
            iteration++;
        }
        return expandedKeys;
    }

    private void generateNextBytes(byte[] expandedKeys, AesKeyParam aesKeyParams, int iteration, HashDirection direction) {
        int bufferPosition = iteration * aesKeyParams.getLengthBytes();
        byte[] temporary = new byte[4];
        System.arraycopy(expandedKeys, bufferPosition - 4, temporary, 0, 4);
        temporary = AesUtils.scheduleCore(temporary, iteration);

        for (int i = 0; i < 4; i++) {
            byte[] previousBlock = getPreviousBlock(expandedKeys, bufferPosition, aesKeyParams);
            temporary = exclusiveOrWithPreviousBlock(temporary, previousBlock);
            bufferPosition = savePutToBuffer(expandedKeys, temporary, bufferPosition);
        }

        if (AesKeyParam.KEY_192_BITS.equals(aesKeyParams)) {
            for (int i = 0; i < 2; i++) {
                byte[] previousBlock = getPreviousBlock(expandedKeys, bufferPosition, aesKeyParams);
                temporary = exclusiveOrWithPreviousBlock(temporary, previousBlock);
                bufferPosition = savePutToBuffer(expandedKeys, temporary, bufferPosition);
            }
        }

        if (AesKeyParam.KEY_256_BITS.equals(aesKeyParams)) {
            temporary = AesUtils.applySBox(temporary, direction);
            for (int i = 0; i < 4; i++) {
                byte[] previousBlock = getPreviousBlock(expandedKeys, bufferPosition, aesKeyParams);
                temporary = exclusiveOrWithPreviousBlock(temporary, previousBlock);
                bufferPosition = savePutToBuffer(expandedKeys, temporary, bufferPosition);
            }
        }
    }

    private byte[] getPreviousBlock(byte[] expandedKeys, int bufferPosition, AesKeyParam aesKeyParams) {
        byte[] previousBlock = new byte[4];
        System.arraycopy(expandedKeys, bufferPosition - aesKeyParams.getLengthBytes(), previousBlock, 0, 4);
        return previousBlock;
    }

    private byte[] exclusiveOrWithPreviousBlock(byte[] input, byte[] previousBlock) {
        byte[] output = new byte[4];
        for (int i = 0; i < 4; i++) {
            output[i] = (byte) ((input[i] ^ previousBlock[i]) & 0xFF);
        }
        return output;
    }

    private int savePutToBuffer(byte[] destination, byte[] source, int bufferPosition) {
        int currentPosition = bufferPosition;
        for (byte sourceByte : source) {
            if (currentPosition >= destination.length) {
                return currentPosition;
            }
            destination[currentPosition] = sourceByte;
            currentPosition++;
        }
        return currentPosition;
    }
}
