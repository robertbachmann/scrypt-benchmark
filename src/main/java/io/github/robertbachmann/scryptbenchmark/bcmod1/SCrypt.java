package io.github.robertbachmann.scryptbenchmark.bcmod1;

import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/**
 * Implementation of the scrypt a password-based key derivation function.
 * <p>
 * Scrypt was created by Colin Percival and is specified in <a
 * href="http://tools.ietf.org/html/draft-josefsson-scrypt-kdf-01">draft-josefsson-scrypt-kd</a>
 *
 */
public class SCrypt
{
    /**
     * Generate a key using the scrypt key derivation function.
     * 
     * @param P the bytes of the pass phrase.
     * @param S the salt to use for this invocation.
     * @param N CPU/Memory cost parameter. Must be larger than 1, a power of 2 and less than
     *            <code>2^(128 * r / 8)</code>.
     * @param r the block size, must be >= 1.
     * @param p Parallelization parameter. Must be a positive integer less than or equal to
     *            <code>Integer.MAX_VALUE / (128 * r * 8)</code>.
     * 
     * @param dkLen the length of the key to generate.
     * @return the generated key.
     */
    public static byte[] generate(byte[] P, byte[] S, int N, int r, int p, int dkLen)
    {
        if (P== null)
        {
            throw new IllegalArgumentException("Passphrase P must be provided.");
        }
        if (S == null)
        {
            throw new IllegalArgumentException("Salt S must be provided.");
        }
        if (N <= 1)
        {
            throw new IllegalArgumentException("Cost parameter N must be > 1.");
        }
        // Only value of r that cost (as an int) could be exceeded for is 1
        if (r == 1 && N > 65536)
        {
            throw new IllegalArgumentException("Cost parameter N must be > 1 and < 65536.");
        }
        if (r < 1)
        {
            throw new IllegalArgumentException("Block size r must be >= 1.");
        }
        int maxParallel = Integer.MAX_VALUE / (128 * r * 8);
        if (p < 1 || p > maxParallel)
        {
            throw new IllegalArgumentException("Parallelisation parameter p must be >= 1 and <= " + maxParallel
                + " (based on block size r of " + r + ")");
        }
        if (dkLen < 1)
        {
            throw new IllegalArgumentException("Generated key length dkLen must be >= 1.");
        }
        return MFcrypt(P, S, N, r, p, dkLen);
    }

    private static byte[] MFcrypt(byte[] P, byte[] S, int N, int r, int p, int dkLen)
    {
        int MFLenBytes = r * 128;
        byte[] bytes = SingleIterationPBKDF2(P, S, p * MFLenBytes);

        int[] B = null;

        try
        {
            int BLen = bytes.length >>> 2;
            B = new int[BLen];

            Pack.littleEndianToInt(bytes, 0, B);

            int MFLenWords = MFLenBytes >>> 2;
            for (int BOff = 0; BOff < BLen; BOff += MFLenWords)
            {
                // TODO These can be done in parallel threads
                SMix(B, BOff, N, r);
            }

            Pack.intToLittleEndian(B, bytes, 0);

            return SingleIterationPBKDF2(P, bytes, dkLen);
        }
        finally
        {
            Clear(bytes);
            Clear(B);
        }
    }

    private static byte[] SingleIterationPBKDF2(byte[] P, byte[] S, int dkLen)
    {
        PBEParametersGenerator pGen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        pGen.init(P, S, 1);
        KeyParameter key = (KeyParameter) pGen.generateDerivedMacParameters(dkLen * 8);
        return key.getKey();
    }


    private static void SMix(int[] B, int BOff, int N, int r)
    {
        int BCount = r * 32;

        int[] blockX1 = new int[16];
        int[] blockX2 = new int[16];
        int[] blockY = new int[BCount];

        int[] X = new int[BCount];
        int[][] V = new int[N][];

        try
        {
            System.arraycopy(B, BOff, X, 0, BCount);

            for (int i = 0; i < N; ++i)
            {
                V[i] = Arrays.clone(X);
                BlockMix(X, blockX1, blockX2, blockY, r);
            }

            int mask = N - 1;
            for (int i = 0; i < N; ++i)
            {
                int j = X[BCount - 16] & mask;
                Xor(X, V[j], 0, X);
                BlockMix(X, blockX1, blockX2, blockY, r);
            }

            System.arraycopy(X, 0, B, BOff, BCount);
        }
        finally
        {
            ClearAll(V);
            ClearAll(new int[][]{ X, blockX1, blockX2, blockY });
        }
    }

    private static void BlockMix(int[] B, int[] X1, int[] X2, int[] Y, int r)
    {
        System.arraycopy(B, B.length - 16, X1, 0, 16);

        int BOff = 0, YOff = 0, halfLen = B.length >>> 1;

        for (int i = 2 * r; i > 0; --i)
        {
            Xor(X1, B, BOff, X2);

            salsaCore(8, X2, X1);
            System.arraycopy(X1, 0, Y, YOff, 16);

            YOff = halfLen + BOff - YOff;
            BOff += 16;
        }

        System.arraycopy(Y, 0, B, 0, Y.length);
    }

    public static void salsaCore(int rounds, int[] input, int[] x)
    {
        if (input.length != 16)
        {
            throw new IllegalArgumentException();
        }
        if (x.length != 16)
        {
            throw new IllegalArgumentException();
        }
        if (rounds % 2 != 0)
        {
            throw new IllegalArgumentException("Number of rounds must be even");
        }

        int x00 = input[ 0];
        int x01 = input[ 1];
        int x02 = input[ 2];
        int x03 = input[ 3];
        int x04 = input[ 4];
        int x05 = input[ 5];
        int x06 = input[ 6];
        int x07 = input[ 7];
        int x08 = input[ 8];
        int x09 = input[ 9];
        int x10 = input[10];
        int x11 = input[11];
        int x12 = input[12];
        int x13 = input[13];
        int x14 = input[14];
        int x15 = input[15];

        for (int i = rounds; i > 0; i -= 2)
        {
            x04 ^= rotl(x00 + x12, 7);
            x08 ^= rotl(x04 + x00, 9);
            x12 ^= rotl(x08 + x04, 13);
            x00 ^= rotl(x12 + x08, 18);
            x09 ^= rotl(x05 + x01, 7);
            x13 ^= rotl(x09 + x05, 9);
            x01 ^= rotl(x13 + x09, 13);
            x05 ^= rotl(x01 + x13, 18);
            x14 ^= rotl(x10 + x06, 7);
            x02 ^= rotl(x14 + x10, 9);
            x06 ^= rotl(x02 + x14, 13);
            x10 ^= rotl(x06 + x02, 18);
            x03 ^= rotl(x15 + x11, 7);
            x07 ^= rotl(x03 + x15, 9);
            x11 ^= rotl(x07 + x03, 13);
            x15 ^= rotl(x11 + x07, 18);

            x01 ^= rotl(x00 + x03, 7);
            x02 ^= rotl(x01 + x00, 9);
            x03 ^= rotl(x02 + x01, 13);
            x00 ^= rotl(x03 + x02, 18);
            x06 ^= rotl(x05 + x04, 7);
            x07 ^= rotl(x06 + x05, 9);
            x04 ^= rotl(x07 + x06, 13);
            x05 ^= rotl(x04 + x07, 18);
            x11 ^= rotl(x10 + x09, 7);
            x08 ^= rotl(x11 + x10, 9);
            x09 ^= rotl(x08 + x11, 13);
            x10 ^= rotl(x09 + x08, 18);
            x12 ^= rotl(x15 + x14, 7);
            x13 ^= rotl(x12 + x15, 9);
            x14 ^= rotl(x13 + x12, 13);
            x15 ^= rotl(x14 + x13, 18);
        }

        x[ 0] = x00 + input[ 0];
        x[ 1] = x01 + input[ 1];
        x[ 2] = x02 + input[ 2];
        x[ 3] = x03 + input[ 3];
        x[ 4] = x04 + input[ 4];
        x[ 5] = x05 + input[ 5];
        x[ 6] = x06 + input[ 6];
        x[ 7] = x07 + input[ 7];
        x[ 8] = x08 + input[ 8];
        x[ 9] = x09 + input[ 9];
        x[10] = x10 + input[10];
        x[11] = x11 + input[11];
        x[12] = x12 + input[12];
        x[13] = x13 + input[13];
        x[14] = x14 + input[14];
        x[15] = x15 + input[15];
    }

    /**
     * Rotate left
     *
     * @param   x   value to rotate
     * @param   y   amount to rotate x
     *
     * @return  rotated x
     */
    protected static int rotl(int x, int y)
    {
        return (x << y) | (x >>> -y);
    }

    private static void Xor(int[] a, int[] b, int bOff, int[] output)
    {
        for (int i = output.length - 1; i >= 0; --i)
        {
            output[i] = a[i] ^ b[bOff + i];
        }
    }

    private static void Clear(byte[] array)
    {
        if (array != null)
        {
            Arrays.fill(array, (byte)0);
        }
    }

    private static void Clear(int[] array)
    {
        if (array != null)
        {
            Arrays.fill(array, 0);
        }
    }

    private static void ClearAll(int[][] arrays)
    {
        for (int i = 0; i < arrays.length; ++i)
        {
            Clear(arrays[i]);
        }
    }
}
