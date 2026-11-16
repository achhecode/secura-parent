package com.achhecode.securacore.core;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

import static org.junit.jupiter.api.Assertions.*;

class SecuraTest {
    // Low-cost Argon2 so tests are fast; production uses new Argon2idDeriver().
    final SecuraStream s = new SecuraStream(new Argon2idDeriver(1024, 1));
    final char[] pw = "correct horse".toCharArray();

    @Test void unicodeMessageRoundTrip() {
        var m = new MessageCrypto(s); String t = "नमस्ते 🔐 こんにちは";
        assertEquals(t, m.decrypt(m.encrypt(t, pw), pw));
    }
    @Test void wrongPasswordFails() {
        byte[] c = s.encrypt("x".getBytes(), pw);
        assertThrows(CryptoFailureException.class, () -> s.decrypt(c, "nope".toCharArray()));
    }
    @Test void boundarySizesRoundTrip() {
        for (int n : new int[]{0, 1, SecuraStream.CHUNK - 1, SecuraStream.CHUNK, SecuraStream.CHUNK + 1, 3 * SecuraStream.CHUNK}) {
            byte[] d = new byte[n]; new Random(n).nextBytes(d);
            assertArrayEquals(d, s.decrypt(s.encrypt(d, pw), pw), "size " + n);
        }
    }
    @Test void tamperingAnywhereIsRejected() {
        byte[] c = s.encrypt(new byte[200_000], pw);
        for (int i = 0; i < c.length; i += 997) { byte[] t = c.clone(); t[i] ^= 1;
            assertThrows(CryptoFailureException.class, () -> s.decrypt(t, pw), "offset " + t.length); }
    }
    @Test void truncationAndChunkDropRejected() {
        byte[] c = s.encrypt(new byte[3 * SecuraStream.CHUNK], pw);
        int full = SecuraStream.CHUNK + SecuraStream.TAG;
        assertThrows(CryptoFailureException.class, () -> s.decrypt(Arrays.copyOf(c, c.length - 1), pw));
        assertThrows(CryptoFailureException.class, () -> s.decrypt(Arrays.copyOf(c, c.length - full), pw)); // dropped last chunk
    }
    @Test void noncesAndSaltsDiffer() {
        assertFalse(Arrays.equals(s.encrypt("a".getBytes(), pw), s.encrypt("a".getBytes(), pw)));
    }
    @Test void masterDirectoryBlocksEscapes(@TempDir Path tmp) throws IOException {
        Path root = Files.createDirectory(tmp.resolve("root")); Path outside = Files.createDirectory(tmp.resolve("outside"));
        var md = new MasterDirectory(root);
        assertThrows(CryptoFailureException.class, () -> md.existing("../outside"));
        Files.createSymbolicLink(root.resolve("link"), outside);
        assertThrows(CryptoFailureException.class, () -> md.existing("link"));
        assertThrows(CryptoFailureException.class, () -> md.newPath("link/new.txt"));
    }
    @Test void folderRoundTripAndZipSlip(@TempDir Path tmp) throws IOException {
        Path src = Files.createDirectories(tmp.resolve("src/sub")); Files.writeString(src.resolve("a.txt"), "hello");
        Files.writeString(tmp.resolve("src/sub/b.md"), "# hi"); Files.write(tmp.resolve("src/img.png"), new byte[]{1});
        var fc = new FolderCrypto(s, FileTypes.defaults()); Path enc = tmp.resolve("src.secura");
        fc.encrypt(tmp.resolve("src"), enc, pw); fc.decrypt(enc, tmp.resolve("out"), pw);
        assertEquals("hello", Files.readString(tmp.resolve("out/sub/a.txt")));
        assertFalse(Files.exists(tmp.resolve("out/img.png")));
        // malicious archive encrypted with the right password must still be refused
        var bos = new ByteArrayOutputStream();
        try (var z = new ZipOutputStream(bos)) { z.putNextEntry(new ZipEntry("../evil.txt")); z.write(1); z.closeEntry(); }
        Path evil = tmp.resolve("evil.secura"); Files.write(evil, s.encrypt(bos.toByteArray(), pw));
        assertThrows(CryptoFailureException.class, () -> fc.decrypt(evil, tmp.resolve("out2"), pw));
        assertFalse(Files.exists(tmp.resolve("evil.txt")));
    }
    @Test void fileSignatureChecked() {
        var ft = FileTypes.defaults();
        assertThrows(CryptoFailureException.class, () -> ft.validate("fake.pdf", new ByteArrayInputStream("not a pdf".getBytes())));
        assertDoesNotThrow(() -> ft.validate("ok.pdf", new ByteArrayInputStream("%PDF-1.7".getBytes(StandardCharsets.US_ASCII))));
    }
}
