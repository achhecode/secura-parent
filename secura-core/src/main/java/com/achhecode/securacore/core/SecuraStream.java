package com.achhecode.securacore.core;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Streaming AES-256-GCM, "STREAM" construction.
 * Format: "SCR2" | ver(1) | salt(16) | noncePrefix(7) | chunk_0 | chunk_1 | ...
 * Each chunk = 64 KiB plaintext -> ciphertext||tag(16). Nonce = prefix(7) | counter(4) | lastFlag(1).
 * The header is AAD for every chunk; the last-chunk flag makes truncation and reordering detectable.
 * Each chunk is authenticated before its plaintext is returned. Callers that write to disk
 * should write to a temp file and only publish it after decrypt() returns (see FileCrypto).
 */
public final class SecuraStream {
    private static final byte[] MAGIC = {'S', 'C', 'R', '2'};
    private static final int VERSION = 1, SALT = 16, PREFIX = 7, HEADER = 4 + 1 + SALT + PREFIX;
    static final int CHUNK = 64 * 1024, TAG = 16;

    private final KeyDeriver kdf;
    private final SecureRandom random = new SecureRandom();

    public SecuraStream(KeyDeriver kdf) { this.kdf = kdf; }

    public void encrypt(InputStream in, OutputStream out, char[] password) throws IOException {
        byte[] salt = new byte[SALT], prefix = new byte[PREFIX];
        random.nextBytes(salt); random.nextBytes(prefix);
        byte[] header = ByteBuffer.allocate(HEADER).put(MAGIC).put((byte) VERSION).put(salt).put(prefix).array();
        byte[] key = kdf.derive(password, salt);
        try {
            var k = new SecretKeySpec(key, "AES");
            out.write(header);
            byte[] cur = in.readNBytes(CHUNK);
            for (int i = 0; ; i++) {
                byte[] next = cur.length == CHUNK ? in.readNBytes(CHUNK) : new byte[0];
                boolean last = next.length == 0;
                out.write(crypt(Cipher.ENCRYPT_MODE, k, prefix, i, last, header, cur));
                if (last) break;
                cur = next;
            }
        } finally { Arrays.fill(key, (byte) 0); }
    }

    public void decrypt(InputStream in, OutputStream out, char[] password) throws IOException {
        byte[] header = in.readNBytes(HEADER);
        if (header.length != HEADER || !Arrays.equals(Arrays.copyOf(header, 4), MAGIC) || header[4] != VERSION)
            throw fail(null);
        byte[] salt = Arrays.copyOfRange(header, 5, 5 + SALT), prefix = Arrays.copyOfRange(header, 5 + SALT, HEADER);
        byte[] key = kdf.derive(password, salt);
        try {
            var k = new SecretKeySpec(key, "AES");
            byte[] cur = in.readNBytes(CHUNK + TAG);
            for (int i = 0; ; i++) {
                byte[] next = cur.length == CHUNK + TAG ? in.readNBytes(CHUNK + TAG) : new byte[0];
                boolean last = next.length == 0;
                out.write(crypt(Cipher.DECRYPT_MODE, k, prefix, i, last, header, cur));
                if (last) break;
                cur = next;
            }
        } finally { Arrays.fill(key, (byte) 0); }
    }

    public byte[] encrypt(byte[] data, char[] pw) {
        try { var o = new ByteArrayOutputStream(); encrypt(new ByteArrayInputStream(data), o, pw); return o.toByteArray(); }
        catch (IOException e) { throw fail(e); }
    }
    public byte[] decrypt(byte[] data, char[] pw) {
        try { var o = new ByteArrayOutputStream(); decrypt(new ByteArrayInputStream(data), o, pw); return o.toByteArray(); }
        catch (IOException e) { throw fail(e); }
    }

    private static byte[] crypt(int mode, SecretKeySpec k, byte[] prefix, int counter, boolean last, byte[] aad, byte[] data) {
        if (counter < 0) throw fail(null);
        byte[] nonce = ByteBuffer.allocate(12).put(prefix).putInt(counter).put((byte) (last ? 1 : 0)).array();
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(mode, k, new GCMParameterSpec(128, nonce));
            c.updateAAD(aad);
            return c.doFinal(data);
        } catch (GeneralSecurityException e) { throw fail(e); }
    }

    private static CryptoFailureException fail(Throwable c) {
        return new CryptoFailureException("Decryption failed: wrong password or data was modified", c);
    }
}
