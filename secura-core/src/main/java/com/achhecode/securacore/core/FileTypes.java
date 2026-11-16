package com.achhecode.securacore.core;

import java.io.*;
import java.nio.file.Path;
import java.util.*;

/** Extension allow-list plus real signature check (not just the file name). */
public final class FileTypes {
    private final Set<String> allowed;
    public FileTypes(Collection<String> allowed) { this.allowed = new HashSet<>(allowed.stream().map(String::toLowerCase).toList()); }
    public static FileTypes defaults() { return new FileTypes(List.of("txt", "md", "pdf", "docx", "doc")); }

    public String extension(String name) { int i = name.lastIndexOf('.'); return i < 0 ? "" : name.substring(i + 1).toLowerCase(); }
    public boolean isAllowed(String name) { return allowed.contains(extension(name)); }

    public void validate(String name, InputStream in) throws IOException {
        String ext = extension(name);
        if (!allowed.contains(ext)) throw new CryptoFailureException("File type not allowed: ." + ext);
        byte[] h = in.readNBytes(8);
        boolean ok = switch (ext) {
            case "pdf" -> starts(h, '%', 'P', 'D', 'F');
            case "docx" -> starts(h, 'P', 'K', 3, 4);
            case "doc" -> starts(h, 0xD0, 0xCF, 0x11, 0xE0);
            default -> { for (byte b : h) if (b == 0) yield false; yield true; } // txt/md: no NUL bytes
        };
        if (!ok) throw new CryptoFailureException("File content does not match ." + ext);
    }
    private static boolean starts(byte[] h, int... sig) {
        if (h.length < sig.length) return false;
        for (int i = 0; i < sig.length; i++) if ((h[i] & 0xFF) != sig[i]) return false;
        return true;
    }
    public void validate(Path p) throws IOException {
        try (var in = java.nio.file.Files.newInputStream(p)) { validate(p.getFileName().toString(), in); }
    }
}
