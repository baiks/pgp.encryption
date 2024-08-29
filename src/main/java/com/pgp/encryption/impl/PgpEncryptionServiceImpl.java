package com.pgp.encryption.impl;


import com.pgp.encryption.services.PgpEncryptionService;
import lombok.extern.log4j.Log4j2;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.bc.BcPGPSecretKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.Streams;
import org.springframework.stereotype.Component;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.util.Date;
import java.util.Iterator;
import java.util.stream.Collectors;

import static com.pgp.encryption.impl.PublicKeyUtil.findSecretKey;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;
import static org.springframework.util.StreamUtils.BUFFER_SIZE;

@Log4j2
@Component
public class PgpEncryptionServiceImpl implements PgpEncryptionService {

    public PgpEncryptionServiceImpl() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            Security.insertProviderAt(new BouncyCastleProvider(), 0);
            log.info("Security provider added successfully");
        }
    }

    public byte[] decryptArmoredAndVerifySignature(final InputStream opsEncrypted, final InputStream pvtKey, final char[] passwd, final InputStream pubKey) throws IOException, NoSuchProviderException, SignatureException, PGPException {
        var opsEncryptedDecoded = PGPUtil.getDecoderStream(opsEncrypted);

        final PGPObjectFactory pgpF = new PGPObjectFactory(opsEncryptedDecoded, new JcaKeyFingerprintCalculator());
        PGPEncryptedDataList enc;
        Long keyID = null;


        final Object o = pgpF.nextObject();
        Object message = null;
        //
        // the first object might be a PGP marker packet.
        //
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else if (o instanceof PGPCompressedData) {
            message = o;
            var comData = new PGPObjectFactory(((PGPCompressedData) o).getDataStream(), new JcaKeyFingerprintCalculator());
            var opsMessage = comData.nextObject();
            keyID = ((PGPOnePassSignatureList) opsMessage).get(0).getKeyID();
            enc = null;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        final Iterator<?> it = nonNull(enc) ? enc.getEncryptedDataObjects() : null;
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        final PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(pvtKey), new JcaKeyFingerprintCalculator());

        if (isNull(enc) || isNull(it)) {
            sKey = findSecretKey(pgpSec, keyID, passwd);
        } else {
            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }
        }

        if (sKey == null) {
            log.error("Could not load the secret/private key into the PGPSecretKeyRingCollection");
            log.error("Hint: Ensure that the Private Key was generated correctly before usage.");
            throw new IllegalArgumentException("secret key for message not found.");
        }

        PGPObjectFactory plainFact = null;
        if (nonNull(enc)) {
            final InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
            plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
            message = plainFact.nextObject();
        }

        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;
        PGPCompressedData compressedData = null;

        final ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

        while (message != null) {
            log.info(message.toString());
            if (message instanceof PGPCompressedData) {
                compressedData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
                message = plainFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                // have to read it and keep it somewhere.
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;
            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
            } else {
                throw new PGPException("message unknown message type.");
            }
            message = plainFact.nextObject();
        }
        actualOutput.close();
        PGPPublicKey publicKey = null;
        byte[] output = actualOutput.toByteArray();
        if (onePassSignatureList == null || signatureList == null) {
            log.error("No signatures found in the PGP Message...");
            log.error("Hint: Ensure that the PGP Message was signed using PGP OnePassSignature methodology.");
            throw new PGPException("Poor PGP Message. Signatures not found.");
        } else {

            for (int i = 0; i < onePassSignatureList.size(); i++) {
                final PGPOnePassSignature ops = onePassSignatureList.get(0);
                log.debug("verifier : " + ops.getKeyID());
                final PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(pubKey), new JcaKeyFingerprintCalculator());
                publicKey = pgpRing.getPublicKey(ops.getKeyID());
                if (publicKey != null) {
                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                    ops.update(output);
                    PGPSignature signature = signatureList.get(i);
                    if (ops.verify(signature)) {
                        final Iterator<?> userIds = publicKey.getUserIDs();
                        while (userIds.hasNext()) {
                            final var userId = (String) userIds.next();
                            log.info("Signed by {}", userId);
                        }
                        log.debug("Signature verified");
                    } else {
                        log.error("Signed by unverified/unknown signatures...");
                        log.error("Hint: Ensure that the correct Private Key used for Signature Signing was shared with Equity Dev-Team, in the Key-Vault");
                        throw new SignatureException("Signature verification failed");
                    }
                }
            }

        }

        if (pbe.isIntegrityProtected() && !pbe.verify()) {
            log.error("Data is encrypted but integrity is lost.");
            log.error("Hint: Ensure that the PGP Message is Integrity Protected during encryption.");
            throw new PGPException("Data is encrypted but integrity is lost.");
        } else if (publicKey == null) {
            log.error("Matching Private Key ID not found from the PGP Message (PGP Public Key). PGP Message encrypted with an unknown/unverified Public Key.");
            log.error("Hint: Ensure that the correct Public key is used.");
            throw new SignatureException("Signature not found");
        }

        return output;
    }

    public byte[] encrypt(final byte[] clearData, final PGPPublicKey encKey) throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        boolean withIntegrityCheck = true;
        String fileName = PGPLiteralData.CONSOLE;

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = new ArmoredOutputStream(encOut);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream cos = comData.open(bOut); // open it with the final
        // destination
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(cos, // the compressed output stream
                PGPLiteralData.BINARY, fileName, // "filename" to store
                clearData.length, // length of clear data
                new Date() // current time
        );
        pOut.write(clearData);
        lData.close();
        comData.close();
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
        byte[] bytes = bOut.toByteArray();
        OutputStream cOut = cPk.open(out, bytes.length);
        cOut.write(bytes); // obtain the actual bytes from the compressed stream
        cOut.close();
        out.close();
        return encOut.toByteArray();
    }

    /**
     * Solution 1 - Decrypts the files according to the parameters passed.
     *
     * @param encrypted The byte-array of the encrypted file to be decrypted.
     * @param password  password of the PGP-Private key.
     * @param pvtKey    Private Key (in {@link InputStream} format). Please trim off
     *                  'BEGIN/END PRIVATE KEY' tags & the checksum (anything after the equal-sign at
     *                  the tail-end of the private-key).
     * @return the primitive variant of the {@link Byte} array.
     * @throws IOException
     * @throws PGPException
     */
    public InputStream decrypt(final InputStream encrypted, final String password, final InputStream pvtKey) throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        final char[] pass = password.toCharArray();
        final InputStream in = PGPUtil.getDecoderStream(encrypted);
        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }
        Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(pvtKey), new JcaKeyFingerprintCalculator());
        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            sKey = findSecretKey(pgpSec, pbe.getKeyID(), pass);
        }
        if (sKey == null) {
            log.error("Public used by the client to encrypt the PGP-Message mismatched with the EQ-Bank Private Key");
            throw new IllegalArgumentException("secret key for message not found.");
        }
        InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
        JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
        PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
        PGPLiteralData ld = null;
        boolean notFound = true;
        while (notFound) {
            try {
                ld = (PGPLiteralData) pgpFact.nextObject();
                notFound = false;
            } catch (ClassCastException cce) {
                log.warn("This is an anticipated warning. {}", cce.getMessage(), cce);
            } catch (Exception ex) {
                log.warn("Warning: {}", ex.getMessage(), ex);
                break;
            }
        }
        final InputStream unc = ld.getInputStream();
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        int ch;
        while ((ch = unc.read()) >= 0) {
            out.write(ch);
        }
        return new ByteArrayInputStream(out.toByteArray());
    }

    /**
     * In light of the greater-complexities & error-prone realizations of the Solution 1
     * a need for simpler version of the PGP-Decryption was explored and this end result is as defined below.
     * Please DO NOT mess around with the PGP-Version-Dependencies in the POM file, unless fully tested on localhost
     * with Unit & Integration tests.
     *
     * @param encryptedFileBytes byte-array of the encrypted file.
     * @param password           tim-off white-spaces from the password. typical/common errors often experienced.
     * @param privateKey         without the 'BEGIN/END PRIVATE KEY' tags. Trim off 'BEGIN/END PRIVATE KEY' tags
     *                           & the checksum (anything after the equal-sign at the tail-end of the private-key).
     * @return {@link InputStream} of the decrypted contents of the file.
     * @throws PGPException
     * @throws IOException
     * @throws NoSuchProviderException
     */
    public InputStream decrypt(InputStream encryptedFileBytes, String password, String privateKey) throws PGPException, IOException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        final PGPSecretKeyRing privateKeyRing = new BcPGPSecretKeyRing(Base64.decode(privateKey));
        final InMemoryKeyring imem = KeyringConfigs.forGpgExportedKeys(KeyringConfigCallbacks.withPassword(password));
        imem.addSecretKeyRing(privateKeyRing);
        log.info("=========>>>>>>>>>>>>>Decryption Initiated<<<<<<<<<<<=============");
        final InputStream plaintextStream = BouncyGPG.decryptAndVerifyStream().withConfig(imem).andIgnoreSignatures().fromEncryptedInputStream(encryptedFileBytes);
        log.info("=========>>>>>>>>>>>>>Decryption Completed Successfully<<<<<<<<<<<=============");
        return plaintextStream;
    }

    /**
     * Use this decryption method when the PGP file is encrypted with OnePassSignature.
     * The PGP file is decrypted & the signature immediately verified.
     * <p>
     * Note: Do not use this method when the encrypted PGP file is not signed.
     *
     * @param encrypted encrypted contents/data
     * @param password  for the Private Key
     * @param pvtKeyIs  Private Key in String format.
     * @param privKey   Private Key in String format.
     * @param armored   ASCII Armored PGP-Message encrypted contents?
     * @return successfully decrypted contents(in Byte Array) of the PGP File, after a successful signature verification.
     * @throws IOException        Missing PGP Data
     * @throws PGPException       thrown when unidentified data packets have been found in the PGPObjectFactory.
     * @throws SignatureException when the signature verification fails.
     */
    @Override
    public byte[] decryptAndVerifySignature(final byte[] encrypted, final String password, final InputStream pvtKeyIs, final InputStream privKey, final Boolean armored) throws IOException, PGPException, SignatureException {
        final InputStream in = armored ? new ArmoredInputStream(new ByteArrayInputStream(encrypted), true) : new ByteArrayInputStream(encrypted);
        PGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
        PGPEncryptedDataList enc;

        Object obj = pgpF.nextObject();
        //
        // the first object might be a PGP marker packet.
        //
        if (obj instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) obj;
        } else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }

        //
        // find the secret key
        //
        Iterator<?> it = enc.getEncryptedDataObjects();
        PGPPrivateKey sKey = null;
        PGPPublicKeyEncryptedData pbe = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(pvtKeyIs), new JcaKeyFingerprintCalculator());

        while (sKey == null && it.hasNext()) {
            pbe = (PGPPublicKeyEncryptedData) it.next();
            sKey = findSecretKey(pgpSec, pbe.getKeyID(), password.toCharArray());
        }

        if (sKey == null) {
            log.error("The public key used for encryption not doesn't belong to the key-pair.");
            throw new IllegalArgumentException("secret key for message not found.");
        }

        final InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
        PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());

        PGPOnePassSignatureList onePassSignatureList = null;
        PGPSignatureList signatureList = null;
        PGPCompressedData compressedData = null;

        Object message = plainFact.nextObject();
        ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();

        while (message != null) {
            log.trace(message.toString());
            if (message instanceof PGPCompressedData) {
                compressedData = (PGPCompressedData) message;
                plainFact = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
                message = plainFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                // have to read it and keep it somewhere.
                Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
            } else if (message instanceof PGPOnePassSignatureList) {
                onePassSignatureList = (PGPOnePassSignatureList) message;
                log.info("Total PGPOnePassSignatureList found: {}", onePassSignatureList.size());
            } else if (message instanceof PGPSignatureList) {
                signatureList = (PGPSignatureList) message;
                log.info("Total PGPSignatureList found: {}", signatureList.size());
            } else {
                throw new PGPException("message unknown message type.");
            }
            message = plainFact.nextObject();
        }
        log.info("PGP-Signature found?: {}", nonNull(signatureList));

        actualOutput.close();
        PGPPublicKey publicKey = null;

        byte[] output = actualOutput.toByteArray();
        if (onePassSignatureList == null && signatureList == null) {
            log.error("Could not verify the PGP Signature");
            log.error("Neither PGPOnePassSignature nor PGPSignature were found.");
            log.error("No PGP-Signatures found on the PGP-Encrypted file expected to be decrypted.");
            throw new PGPException("No PGP-Signatures found on the PGP-Encrypted file expected to be decrypted.");
        } else if (signatureList != null) {
            final PGPSignature ops = signatureList.get(0);
            log.trace("PGPSignature Verifier : {}", ops.getKeyID());
            PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(privKey), new BcKeyFingerprintCalculator());
            publicKey = pgpRing.getPublicKey(ops.getKeyID());
            if (publicKey != null) {
                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                ops.update(output);
                if (ops.verify()) {
                    final Iterator<?> userIds = publicKey.getUserIDs();
                    while (userIds.hasNext()) {
                        String userId = (String) userIds.next();
                        log.info("PGPSignature file Signed by {}", userId);
                    }
                    log.info("Signature verified");
                } else {
                    throw new SignatureException("Signature verification failed");
                }
            }
        } else {

            for (int i = 0; i < onePassSignatureList.size(); i++) {
                final PGPOnePassSignature ops = onePassSignatureList.get(0);
                log.info("PGPOnePassSignature Verifier: {}", ops.getKeyID());
                final PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(privKey), new BcKeyFingerprintCalculator());
                publicKey = pgpRing.getPublicKey(ops.getKeyID());
                if (publicKey != null) {
                    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
                    ops.update(output);
                    final PGPSignature signature = signatureList.get(i);
                    if (ops.verify(signature)) {
                        final Iterator<?> userIds = publicKey.getUserIDs();
                        while (userIds.hasNext()) {
                            String userId = (String) userIds.next();
                            log.info("PGPOnePassSignature file Signed by {}", userId);
                        }
                        log.info("PGPOnePassSignature verified");
                    } else {
                        throw new SignatureException("PGPOnePassSignature verification failed");
                    }
                }
            }

        }

        if (pbe.isIntegrityProtected() && !pbe.verify()) {
            log.error("************PGP Signature Verification Failure**********");
            log.error("PGP File decrypted successfully but the signature verification failed!!! File has been tampered with. Do not trust file.");
            log.error("************PGP Signature Verification Failure**********");
            throw new SignatureException("PGP File decrypted successfully but the signature verification failed!!! File has been tampered with. Do not trust file.");
        } else if (publicKey == null) {
            throw new SignatureException("Signature not found");
        } else {
            return output;
        }
    }

    @Override
    public final byte[] encrypt(final byte[] clearData, final String publicKey, final String privateKey, final String privateKeyPass, final String fileName) throws IOException, PGPException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        final PGPPublicKey pgpPublicKey = PublicKeyUtil.readPublicKey(publicKey.getBytes(UTF_8));

        final ByteArrayOutputStream outerEncryptionStream = new ByteArrayOutputStream();
        final ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outerEncryptionStream);
        armoredOutputStream.write(clearData);

        final PGPSecretKey secretKey = PublicKeyUtil.readSecretKey(new ByteArrayInputStream(privateKey.getBytes(UTF_8)));
        final PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(privateKeyPass.toCharArray()));
        final PGPSignatureGenerator sGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA512).setProvider("BC"));
        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
//        sGen.update();
        final Iterator<String> userIDs = secretKey.getPublicKey().getUserIDs();
        if (userIDs.hasNext()) {
            final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userIDs.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

//       final ByteArrayOutputStream out = new ByteArrayOutputStream();
//        out.write(clearData);

        final PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));
        final OutputStream encryptedOut = encGen.open(armoredOutputStream, new byte[BUFFER_SIZE]);

//        final ByteArrayOutputStream outerEncryptionStream = new ByteArrayOutputStream();
//        final ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(encryptedOut);

//        final PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
//        final OutputStream compressionStream = comData.open(encryptedOut);

        sGen.generateOnePassVersion(false).encode(encryptedOut); // bOut

        final PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        final OutputStream lOut = lGen.open(encryptedOut, // the compressed output stream
                PGPLiteralData.BINARY, "MPESA_EQUITY_BANK_HEAD_OFFICE_NHIF_BUILDING_Statement_202204111921.csv.pgp", // "filename" to store // length of clear data
                new Date(), // current time
                new byte[BUFFER_SIZE]);
//        armoredOutputStream.close();
//        outerEncryptionStream.flush();
        final byte[] arrOut = outerEncryptionStream.toByteArray();

        lOut.write(arrOut);
        sGen.update(arrOut);

        lOut.close();
        lGen.close();

//        compressionStream.close();

        sGen.generate().encode(armoredOutputStream);
//        outerEncryptionStream.flush();
        outerEncryptionStream.close();

//        armoredOutputStream.flush();
        armoredOutputStream.close();

//        return outerEncryptionStream.toByteArray();
        log.info("outerEncryptionStream: \n{}", outerEncryptionStream.toString());
        log.info("ByteArray: \n{}", new String(arrOut));

        return outerEncryptionStream.toByteArray();
    }

    /**
     * GPG Option to Decrypt files.
     *
     * @param password
     * @param pathToEncryptedFile
     * @param outputFilePathWithExtension
     * @throws IOException
     */
    public void decryptArmoredAndVerifySignature(String password, String pathToEncryptedFile, String outputFilePathWithExtension) throws IOException {
        String[] gpgCommands = new String[]{"gpg", "--passphrase", password, "--decrypt", pathToEncryptedFile, "--output", outputFilePathWithExtension};

        Process gpgProcess = Runtime.getRuntime().exec(gpgCommands);
        try (BufferedReader gpgOutput = new BufferedReader(new InputStreamReader(gpgProcess.getInputStream()))) {
            log.info("GPG Response: {}", gpgOutput.lines().collect(Collectors.joining("\n")));
        }

        try (BufferedReader gpgError = new BufferedReader(new InputStreamReader(gpgProcess.getErrorStream()))) {
            log.info("GPG Errors: {}", gpgError.lines().collect(Collectors.joining("\n")));
        }
    }

    /**
     * OnePass Encryption which first signs the contents & followed by encryption of the clearData.
     * OnePass encryption methodology is a sequence of steps done concurrently, starting with signature signing
     * and then lastly with file encryption in a single execution of this method.
     * <p>
     * Sign with the private Key & encrypt with the public key.
     *
     * @param clearData      the content to be signed & encrypted.
     * @param publicKey      public key (From the Client) proposed to be used for encryption.
     * @param privateKey     Private key which must be generated by Equity Bank. Private key is used for signature signing.
     * @param privateKeyPass passphrase needed to unlock the secured private key. This passphrase is accompanied by the Private-Key.
     * @param fileName       Filename the file encrypted/generated PGP File.
     * @return Signed & Encrypted contents (using One-Pass signature signing & encryption) in byte array.
     * @throws IOException
     * @throws PGPException
     * @throws SignatureException
     */
    @Override
    public final byte[] signAndEncrypt(final byte[] clearData, final String publicKey, final String privateKey, final String privateKeyPass, final String fileName) throws IOException, PGPException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        final PGPPublicKey pgpPublicKey = PublicKeyUtil.readPublicKey(publicKey.getBytes(UTF_8));
        final PGPSecretKey secretKey = PublicKeyUtil.readSecretKey(new ByteArrayInputStream(privateKey.getBytes(UTF_8)));
        final PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(privateKeyPass.toCharArray()));

        final ByteArrayOutputStream outerEncryptedStream = new ByteArrayOutputStream();
        final ArmoredOutputStream armoredOutput = new ArmoredOutputStream(outerEncryptedStream);
//        final PGPEncryptedDataGenerator crypter = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(PGPEncryptedData.CAST5)); //PGPEncryptedData.CAST5
        final PGPEncryptedDataGenerator crypter = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(pgpPublicKey.getPublicKeyPacket().getAlgorithm()).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()));
        crypter.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pgpPublicKey).setProvider("BC"));
        final BCPGOutputStream pgpOut = new BCPGOutputStream(crypter.open(armoredOutput, new byte[BUFFER_SIZE]));

        /* Prepare for signing */
        final PGPSignatureGenerator signer = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA512).setProvider("BC"));
        signer.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        /* Output the standard header */
        signer.generateOnePassVersion(false).encode(pgpOut);

        /* Output the literal data */
        final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator(true);
        literalDataGenerator.open(pgpOut, PGPLiteralData.BINARY, fileName, //ignored. Not relevant.
                clearData.length, new Date()).write(clearData); //

        /* Calculate signature and output it */
        signer.update(clearData);
        signer.generate().encode(pgpOut);

        pgpOut.close();
        armoredOutput.close();
        outerEncryptedStream.close();

        return outerEncryptedStream.toByteArray();
    }
}
