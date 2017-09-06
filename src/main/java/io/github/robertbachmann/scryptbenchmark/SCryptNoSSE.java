// Copyright (C) 2011 - Will Glozer.  All rights reserved.

package io.github.robertbachmann.scryptbenchmark;

import com.lambdaworks.jni.LibraryLoader;
import com.lambdaworks.jni.LibraryLoaders;

/**
 * An implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt</a>
 * key derivation function. This class will attempt to load a native library
 * containing the optimized C implementation from
 * <a href="http://www.tarsnap.com/scrypt.html">http://www.tarsnap.com/scrypt.html<a> and
 * fall back to the pure Java version if that fails.
 *
 * @author  Will Glozer
 */
public class SCryptNoSSE {
    private static final boolean native_library_loaded;

    static {
        LibraryLoader loader = LibraryLoaders.loader();
        native_library_loaded = loader.load("scryptnosse", true);
    }

    /**
     * Native C implementation of the <a href="http://www.tarsnap.com/scrypt/scrypt.pdf"/>scrypt KDF</a> using
     * the code from <a href="http://www.tarsnap.com/scrypt.html">http://www.tarsnap.com/scrypt.html<a>.
     *
     * @param passwd    Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     */
    public static native byte[] scryptN(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen);
}
