package com.achhecode.securacore.core;

/** Password -> 32-byte key. Production implementation: Argon2idDeriver. */
@FunctionalInterface
public interface KeyDeriver { byte[] derive(char[] password, byte[] salt); }
