package com.achhecode.securacore.core;

import java.io.IOException;
import java.nio.file.*;

/** Confines all file/folder work to one root. Blocks "..", absolute escapes and symlink escapes. */
public final class MasterDirectory {
    private final Path root;

    public MasterDirectory(Path root) {
        try { this.root = root.toRealPath(); } catch (IOException e) { throw new IllegalStateException("Master directory unavailable", e); }
    }
    public Path root() { return root; }

    /** Resolve an existing path (symlinks resolved, then re-checked). */
    public Path existing(String relative) {
        try {
            Path p = root.resolve(relative).normalize().toRealPath();
            if (!p.startsWith(root)) throw new CryptoFailureException("Path outside master directory");
            return p;
        } catch (IOException e) { throw new CryptoFailureException("Path not found", e); }
    }

    /** Resolve a path that must not exist yet (no overwrite); its parent must be inside root. */
    public Path newPath(String relative) {
        Path p = root.resolve(relative).normalize();
        try {
            Path parent = p.getParent().toRealPath();
            if (!parent.startsWith(root)) throw new CryptoFailureException("Path outside master directory");
        } catch (IOException | NullPointerException e) { throw new CryptoFailureException("Invalid target", e); }
        if (Files.exists(p, LinkOption.NOFOLLOW_LINKS)) throw new CryptoFailureException("Target already exists");
        return p;
    }
}
