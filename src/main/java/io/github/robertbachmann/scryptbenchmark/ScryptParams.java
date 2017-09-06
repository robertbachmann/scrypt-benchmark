package io.github.robertbachmann.scryptbenchmark;

public class ScryptParams {
    private int n = 16384;
    private int r = 8;
    private int p = 1;
    private int dkLen = 32;
    private int saltLen = 32;
    private static final byte[] password = "Hello World".getBytes();
    private static final byte[] salt = "SALt".getBytes();


    public ScryptParams() {
    }

    public ScryptParams(int n, int r, int p, int dkLen, int saltLen) {
        this.n = n;
        this.r = r;
        this.p = p;
        this.dkLen = dkLen;
        this.saltLen = saltLen;
    }

    public int getN() {
        return n;
    }

    public void setN(int n) {
        this.n = n;
    }

    public int getR() {
        return r;
    }

    public void setR(int r) {
        this.r = r;
    }

    public int getP() {
        return p;
    }

    public void setP(int p) {
        this.p = p;
    }

    public int getDkLen() {
        return dkLen;
    }

    public void setDkLen(int dkLen) {
        this.dkLen = dkLen;
    }

    public int getSaltLen() {
        return saltLen;
    }

    public void setSaltLen(int saltLen) {
        this.saltLen = saltLen;
    }

    public byte[] getPassword() {
        return password;
    }


    public byte[] getSalt() {
        return salt;
    }
}
