package com.achhecode.securacore.core;

/** Generic, fail-closed error. Never carries plaintext, keys or password info. */
public class CryptoFailureException extends RuntimeException {
    public CryptoFailureException(String m) { super(m); }
    public CryptoFailureException(String m, Throwable c) { super(m, c); }
}
