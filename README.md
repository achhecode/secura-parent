# SECURA (simple edition)
Password-based encryption for messages, files and folders. Argon2id -> AES-256-GCM (streaming, 64 KiB chunks).

    secura-parent/
      secura-core   crypto, message, file-type checks, folder zip, master-directory guard (no Spring)
      secura-web    Spring Boot 4.1.2 + Thymeleaf UI (runnable)

Build/run (JDK 25, Maven 3.9.6+):

    mvn clean verify
    mvn -pl secura-web -am spring-boot:run     # http://127.0.0.1:8080

Notes
- Losing the password means losing the data. There is no recovery.
- Argon2id parameters (64 MiB, t=3, p=1) are fixed for container v1; changing them needs a new version byte.
- No login yet: the server binds to 127.0.0.1. Add authentication before exposing it.
- Folder encryption packs only allowed file types, skips symlinks, hides file names inside the ciphertext.
- Not audited and not certified. No compliance claims.
