package com.achhecode.securacore.core;

import java.io.*;
import java.nio.file.*;
import java.util.zip.*;

/**
 * Folder -> zip -> SecuraStream. The zip (and therefore the file names/structure) is inside the
 * encrypted payload. Symlinks and disallowed types are skipped when packing; extraction is zip-slip
 * safe, never overwrites, and is bounded.
 */
public final class FolderCrypto {
    static final long MAX_TOTAL = 4L << 30; static final int MAX_ENTRIES = 50_000;
    private final SecuraStream stream; private final FileTypes types;
    public FolderCrypto(SecuraStream stream, FileTypes types) { this.stream = stream; this.types = types; }

    public void encrypt(Path folder, Path outFile, char[] pw) throws IOException {
        Path tmp = Files.createTempFile("secura-", ".zip");
        try {
            try (var zip = new ZipOutputStream(Files.newOutputStream(tmp)); var walk = Files.walk(folder)) {
                for (Path p : (Iterable<Path>) walk::iterator) {
                    if (Files.isSymbolicLink(p) || !Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) continue;
                    if (!types.isAllowed(p.getFileName().toString())) continue;
                    types.validate(p);
                    zip.putNextEntry(new ZipEntry(folder.relativize(p).toString().replace('\\', '/')));
                    Files.copy(p, zip); zip.closeEntry();
                }
            }
            try (var in = Files.newInputStream(tmp); var out = Files.newOutputStream(outFile, StandardOpenOption.CREATE_NEW)) {
                stream.encrypt(in, out, pw);
            } catch (IOException | RuntimeException e) { Files.deleteIfExists(outFile); throw e; }
        } finally { Files.deleteIfExists(tmp); }
    }

    public void decrypt(Path encFile, Path targetDir, char[] pw) throws IOException {
        Path tmp = Files.createTempFile("secura-", ".zip");
        try {
            try (var in = Files.newInputStream(encFile); var out = Files.newOutputStream(tmp)) { stream.decrypt(in, out, pw); }
            // only reached if every chunk authenticated
            Files.createDirectory(targetDir);
            Path base = targetDir.toRealPath(); long total = 0; int n = 0;
            try (var zip = new ZipInputStream(Files.newInputStream(tmp))) {
                for (ZipEntry e; (e = zip.getNextEntry()) != null; ) {
                    if (++n > MAX_ENTRIES) throw new CryptoFailureException("Too many entries");
                    Path dest = base.resolve(e.getName()).normalize();
                    if (!dest.startsWith(base) || e.isDirectory() || !types.isAllowed(dest.getFileName().toString()))
                        throw new CryptoFailureException("Unsafe archive entry");
                    Files.createDirectories(dest.getParent());
                    try (var o = Files.newOutputStream(dest, StandardOpenOption.CREATE_NEW)) {
                        byte[] buf = new byte[8192];
                        for (int r; (r = zip.read(buf)) > 0; ) {
                            if ((total += r) > MAX_TOTAL) throw new CryptoFailureException("Archive too large");
                            o.write(buf, 0, r);
                        }
                    }
                }
            }
        } finally { Files.deleteIfExists(tmp); }
    }
}
