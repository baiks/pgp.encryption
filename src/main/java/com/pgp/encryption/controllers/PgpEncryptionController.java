package com.pgp.encryption.controllers;

import com.google.gson.Gson;
import com.pgp.encryption.dtos.DecryptionResponse;
import com.pgp.encryption.dtos.PgpEncryption;
import com.pgp.encryption.impl.PublicKeyUtil;
import com.pgp.encryption.services.PgpEncryptionService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.charset.StandardCharsets;

import static com.pgp.encryption.services.Base64Utils.decode;
import static com.pgp.encryption.services.Base64Utils.stripPgpHeadAndTailAndChecksum;


@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Log4j2
public class PgpEncryptionController {
    private final PgpEncryptionService pgpEncryptionService;

    @GetMapping
    public String ping() {
        return "Ping Successful";
    }

    @RequestMapping(method = RequestMethod.POST, value = "/decrypt")
    public ResponseEntity<String> decryptContent(@RequestBody String request) {
        log.info("Received Request: {}", request);
        PgpEncryption pgpEncryption = new Gson().fromJson(request, PgpEncryption.class);
        try {
            String content = decode(pgpEncryption.getContent());
            String privateKey = decode(pgpEncryption.getPrivatekey());
            final InputStream pkey = new ByteArrayInputStream(stripPgpHeadAndTailAndChecksum(privateKey).getBytes(StandardCharsets.UTF_8));
            final InputStream encryptedData = new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
            final InputStream decrypted = pgpEncryptionService.decrypt(encryptedData, pgpEncryption.getPassphrase(), pkey);
            String result = new String(decrypted.readAllBytes());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error: " + e.getMessage());
        }
    }


//    @PostMapping("/encrypt")
//    public ResponseEntity<byte[]> encryptData1(@RequestParam("filePath") MultipartFile file, @RequestParam("publicKey") MultipartFile publicKeyFile) {
//        try {
//            byte[] clearData = file.getBytes();
//            PGPPublicKey publicKey = PublicKeyUtil.readPublicKey(publicKeyFile);
//            byte[] encryptedData = pgpEncryptionService.encrypt(clearData, publicKey);
//            return ResponseEntity.ok(encryptedData);
//        } catch (IOException | PGPException e) {
//            return ResponseEntity.status(500).body(null);
//        }
//    }
}
 