package io.github.robertbachmann.scryptbenchmark;

import org.bouncycastle.util.encoders.Hex;

import java.security.GeneralSecurityException;

public class Main {
    public static void main(String[] args) throws GeneralSecurityException {
        System.out.println(Hex.toHexString(new MyBenchmark().testScryptBouncyCastle()));
        System.out.println(Hex.toHexString(new MyBenchmark().testScryptBouncyCastle1()));
        System.out.println(Hex.toHexString(new MyBenchmark().testScryptBouncyCastle2()));
        System.out.println(Hex.toHexString(new MyBenchmark().testScryptBouncyCastle3()));
        System.out.println(Hex.toHexString(new MyBenchmark().testScryptBouncyCastle4()));
        System.out.println(Hex.toHexString(new MyBenchmark().testScryptBouncyCastle5()));
    }
}
