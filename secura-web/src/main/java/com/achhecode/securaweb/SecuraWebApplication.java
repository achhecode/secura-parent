
package com.achhecode.securaweb;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.achhecode.securacore.core.*;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class SecuraWebApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecuraWebApplication.class, args);
    }

    @Bean
    SecuraStream stream() {
        return new SecuraStream(new Argon2idDeriver());
    }

    @Bean
    FileTypes fileTypes(
            @Value("${secura.allowed-extensions}") List<String> ext) {
        return new FileTypes(ext);
    }

    @Bean
    MasterDirectory masterDirectory(
            @Value("${secura.master-dir}") String dir) throws Exception {
        return new MasterDirectory(Files.createDirectories(Path.of(dir)));
    }

    @Bean
    MessageCrypto messageCrypto(SecuraStream s) {
        return new MessageCrypto(s);
    }

    @Bean
    FolderCrypto folderCrypto(SecuraStream s, FileTypes t) {
        return new FolderCrypto(s, t);
    }
}
