package io.github.robertbachmann.scryptbenchmark;

import org.openjdk.jmh.annotations.*;

import java.util.concurrent.TimeUnit;

@State(Scope.Thread)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@BenchmarkMode(Mode.AverageTime)
public class MyBenchmark {

    private final ScryptParams params = new ScryptParams();

    @Benchmark
    public void testMethod() {
        // This is a demo/sample template for building your JMH benchmarks. Edit as needed.
        // Put your benchmark code here.
    }

    @Benchmark
    public byte[] testWgScryptNative() {
        return com.lambdaworks.crypto.SCrypt.scryptN(params.getPassword(), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
    }

    @Benchmark
    public byte[] testWgScryptJava() {
        try {
            return com.lambdaworks.crypto.SCrypt.scryptJ(params.getPassword(), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Benchmark
    public byte[] testScryptBouncyCastle() {
        return io.github.robertbachmann.scryptbenchmark.bouncy.SCrypt.generate(params.getPassword(), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
    }

    @Benchmark
    public byte[] testScryptBouncyCastle5() {
        return io.github.robertbachmann.scryptbenchmark.bcmod5.SCrypt.generate(params.getPassword(), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
    }

    @Benchmark
    public byte[] testScryptBouncyCastle1() {
        return io.github.robertbachmann.scryptbenchmark.bcmod1.SCrypt.generate(params.getPassword(), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
    }

    @Benchmark
    public byte[] testScryptBouncyCastle2() {
        return io.github.robertbachmann.scryptbenchmark.bcmod2.SCrypt.generate(params.getPassword(), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
    }

    @Benchmark
    public byte[] testScryptBouncyCastle3() {
        return io.github.robertbachmann.scryptbenchmark.bcmod3.SCrypt.generate(params.getPassword(), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
    }

    @Benchmark
    public byte[] testScryptBouncyCastle4() {
        return io.github.robertbachmann.scryptbenchmark.bcmod4.SCrypt.generate(params.getPassword(), params.getSalt(), params.getN(), params.getR(), params.getP(), params.getDkLen());
    }
}
