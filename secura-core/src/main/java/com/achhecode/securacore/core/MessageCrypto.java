package com.achhecode.securacore.core;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Text <-> copy-pasteable Base64 ciphertext. Unicode safe (UTF-8). */
public final class MessageCrypto {
    private final SecuraStream stream;
    public MessageCrypto(SecuraStream stream) { this.stream = stream; }

    public String encrypt(String text, char[] password) {
        return Base64.getMimeEncoder(76, new byte[]{'\n'})
                .encodeToString(stream.encrypt(text.getBytes(StandardCharsets.UTF_8), password));
    }
    public String decrypt(String armored, char[] password) {
        byte[] raw;
        try { raw = Base64.getMimeDecoder().decode(armored.trim()); }
        catch (IllegalArgumentException e) { throw new CryptoFailureException("Invalid ciphertext", e); }
        return new String(stream.decrypt(raw, password), StandardCharsets.UTF_8);
    }
}
