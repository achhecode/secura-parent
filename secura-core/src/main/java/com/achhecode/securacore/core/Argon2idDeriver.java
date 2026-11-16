package com.achhecode.securacore.core;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/** Argon2id, 64 MiB, 3 passes, 1 lane. These parameters are fixed for container version 1. */
public final class Argon2idDeriver implements KeyDeriver {
    private final int memoryKb, iterations;
    public Argon2idDeriver() { this(64 * 1024, 3); }
    public Argon2idDeriver(int memoryKb, int iterations) { this.memoryKb = memoryKb; this.iterations = iterations; }

    @Override public byte[] derive(char[] password, byte[] salt) {
        var p = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13).withSalt(salt)
                .withIterations(iterations).withMemoryAsKB(memoryKb).withParallelism(1).build();
        var g = new Argon2BytesGenerator(); g.init(p);
        byte[] key = new byte[32]; g.generateBytes(password, key);
        return key;
    }
}
