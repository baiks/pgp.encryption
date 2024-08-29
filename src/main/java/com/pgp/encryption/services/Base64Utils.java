package com.pgp.encryption.services;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;


public class Base64Utils {
    private static final String PUB_KEY_VERSION_REGEX_PREFIX = "(?m)^Version.*$";
    private static final String pubKeyHead = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    private static final String pubKeyTail = "-----END PGP PUBLIC KEY BLOCK-----";
    private static final String priKeyHead = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    private static final String priKeyTail = "-----END PGP PRIVATE KEY BLOCK-----";

    private static final char[] legalChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    public static String encode(String s) {
        return encodeFromBytes(s.getBytes());
    }

    public static String encodeFromBytes(byte[] data) {
        int start = 0;
        int len = data.length;
        StringBuilder sb = new StringBuilder(data.length * 3 / 2);
        int end = len - 3;
        int i = start;
        int n = 0;
        while (i <= end) {
            int d = ((((int) data[i]) & 0x0ff) << 16) | ((((int) data[i + 1]) & 0x0ff) << 8) | (((int) data[i + 2]) & 0x0ff);
            sb.append(legalChars[(d >> 18) & 63]);
            sb.append(legalChars[(d >> 12) & 63]);
            sb.append(legalChars[(d >> 6) & 63]);
            sb.append(legalChars[d & 63]);
            i += 3;
            if (n++ >= 14) {
                n = 0;
                sb.append(" ");
            }
        }
        if (i == start + len - 2) {
            int d = ((((int) data[i]) & 0x0ff) << 16) | ((((int) data[i + 1]) & 255) << 8);
            sb.append(legalChars[(d >> 18) & 63]);
            sb.append(legalChars[(d >> 12) & 63]);
            sb.append(legalChars[(d >> 6) & 63]);
            sb.append("=");
        } else if (i == start + len - 1) {
            int d = (((int) data[i]) & 0x0ff) << 16;
            sb.append(legalChars[(d >> 18) & 63]);
            sb.append(legalChars[(d >> 12) & 63]);
            sb.append("==");
        }
        return sb.toString();
    }

    public static String decode(final String s) {
        return new String(decodeToBytes(s)).trim();
    }

    public static byte[] decodeToBytes(String s) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            decode(s, bos);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        byte[] decodedBytes = bos.toByteArray();
        try {
            bos.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return decodedBytes;
    }

    public static String stripPgpHeadAndTailAndChecksum(final String s) {
        String z = s
                .replace(pubKeyHead, "")
                .replaceAll(PUB_KEY_VERSION_REGEX_PREFIX, "")
                .replace(pubKeyTail, "")
                .replace(priKeyHead, "")
                .replace(priKeyTail, "")
//                .replaceAll(System.lineSeparator(), "")
                .trim();
        final String checkSum = z.substring(z.lastIndexOf("=")); // checksum
        return z.replace(checkSum, "").trim(); //remove checksum
    }

    public static String stripPgpHeadAndTail(final String s) {
        return s
                .replace(pubKeyHead, "")
                .replaceAll(PUB_KEY_VERSION_REGEX_PREFIX, "")
                .replace(pubKeyTail, "")
                .replace(priKeyHead, "")
                .replace(priKeyTail, "")
//                .replaceAll(System.lineSeparator(), "")
                .trim();
    }

    private static void decode(String s, OutputStream os) throws IOException {
        int i = 0;
        int len = s.length();
        while (true) {
            while (i < len && s.charAt(i) <= ' ') {
                i++;
            }
            if (i == len) {
                break;
            }
            int tri = (decode(s.charAt(i)) << 18) + (decode(s.charAt(i + 1)) << 12) + (decode(s.charAt(i + 2)) << 6) + (decode(s.charAt(i + 3)));
            os.write((tri >> 16) & 255);
            if (s.charAt(i + 2) == '=') {
                break;
            }
            os.write((tri >> 8) & 255);
            if (s.charAt(i + 3) == '=') {
                break;
            }
            os.write(tri & 255);
            i += 4;
        }
    }

    private static int decode(char c) {
        if (c >= 'A' && c <= 'Z') {
            return ((int) c) - 65;
        } else if (c >= 'a' && c <= 'z') {
            return ((int) c) - 97 + 26;
        } else if (c >= '0' && c <= '9') {
            return ((int) c) - 48 + 26 + 26;
        } else {
            switch (c) {
                case '+':
                    return 62;
                case '/':
                    return 63;
                case '=':
                    return 0;
                default:
                    throw new RuntimeException("unexpected code: " + c);
            }
        }
    }

//    public static void main(String[] args) {
//        System.out.println(stripPgpHeadAndTail(ss()));
//    }

//    private static String ss(){
//        return "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
//                "Version: PGP Command Line v10.3.2 (Build 12281) (Linux)\n" +
//                "\n" +
//                "mQENBGDkQq8BCADdjXUXduhxgd6cKTQtJkUHn7FJnDbxXdSbCSQiJqmrZ19Yv3rr\n" +
//                "Ai8wyxHR+TGJANN5XUcWP8NiGGL9pfBMKSs9LXuL0Qyu66TAIN5F5aGU0gZku309\n" +
//                "7qm1JNUMpRU6vNXaDXHr2RiIy/+RawAcXlLuAd10IVf7pUW53B/Fs6F4Zg1H4cOq\n" +
//                "2voaI68CRGamFy/qzfA4f/cVTIq6F9UxyV2FY2KCXmJI6itDyYT2dCm629SA73oj\n" +
//                "cTSMBuQ2JDRntqMyFy6q76Ahu2Zckc1FTh3CYhiCLg3T8Zhx7srkOq7ilk7hfZQB\n" +
//                "dUweXEkGD8xQrEFnrejZWt8FkIRrnABvIUt9ABEBAAG0KFNhZmFyaWNvbSBMVERO\n" +
//                "ZXcgPHBncGNsQHNhZmFyaWNvbS5jby5rZT6JAWkEEAECAFMFAmDkQq8wFIAAAAAA\n" +
//                "IAAHcHJlZmVycmVkLWVtYWlsLWVuY29kaW5nQHBncC5jb21wZ3BtaW1lBQsHCAkC\n" +
//                "AhkBBRsDAAAAAhYCBR4BAAAAAxUICgAKCRD6B+jBdY/LLL1dCACGnObs5HQxzApL\n" +
//                "EpNNFFW6pKQGVpoZB+XGi9Ry1bAc7USdjrbyrDE9bdOixVojN20K6n3ZGVzhenn2\n" +
//                "vUJ2qB2HL6wglhHHhr/34/vQj5xMGNoczUMvbim0DaZF7lfg7Ata7bQ19Pduj0ox\n" +
//                "VslXhEMTep0ZodqSNG5aL6LfmAOWsUV7c33ZrUdzVpWH9dkdszLV9kU3xEDgDALL\n" +
//                "DNV1H9FdO09bftnZkriEmHvNIrciZue3h4rG4JmEtUKL1z2tfTJzK7PLWlSBXHL3\n" +
//                "tC/uj0YND4cTrPavDBZuQJCdDE9J8vnxeH/LQQkUB5fzBDFQKmbt4PxQEPYbIW4w\n" +
//                "1RShKUlWuQENBGDkQq8BCADCjT4wG13XHiENWcEayIWxFRdV9YV84FC+V/uyBMnF\n" +
//                "8uIlAAkyn9qolTPrdamMnaom/Yuqf5YDU4RtGt8ILj6SsL2FB8gpSFRLaVgoXg4M\n" +
//                "uK+Eknw9YStfT8JDUyvlAgT7jb6SuVf+bvzkCdnLypA5J0u8afQCkqmGioMZHkQB\n" +
//                "J9pNHqQBH1hXrt3Wy2I23UFzNWnwt0uAEWPSI1WVus4aQmlA+nqF599irxvN5gXw\n" +
//                "Y7OAhM/LYIEFodVuhTlN61lsrDpiJnlXs1zZr9SJMlMu7ak5wGZzwy2dc+o9Tvzn\n" +
//                "DFt0+7RTaMZcPGlUrwt+5jkxTytKCyB89sKsj1gpKHSXABEBAAGJAkEEGAECASsF\n" +
//                "AmDkQrAFGwwAAADAXSAEGQEIAAYFAmDkQq8ACgkQ+91CDBMmx7RwjAgAp1GFXrl0\n" +
//                "aTNDT4ZNYBJQX69F3XTBpcI2w5LeIAVQlkTV5PIsQCb5WAcDtH3M15XPOJ5l7UaM\n" +
//                "m9q7a8mcNTBstcpDX+plrQzBlFu9/bPtl45gVYQjp6qpScAyQCjlKoqE9kJZVHWK\n" +
//                "6zGs7T3xt2luk5DJ2x6OzGl4PEI0jyjndYsRzP5cIkq2FoacwcjZWs0s4x8TeK9F\n" +
//                "qPm+gYURls+llmk3P8FH8onQj59FUtr+U5BA1WZyGES4o8/E1SVGEzUKLltYe1rM\n" +
//                "BoPfyQY2GsPPkOv62SLrMNa/lUn9N2KTnSwvDmVp3RPOxOBs/XXOPHiG8jGeNnIF\n" +
//                "V0kfedcfLwIa9QAKCRD6B+jBdY/LLETyB/9vESCKJEgBNeZ2jtiakUYRozCCh757\n" +
//                "IU06PjcWgOUXt1aGxcmeG+fIgy1p/e8QRxPHL5hbQD/Bck3VyeXjrE9aIDZHqvJs\n" +
//                "kjvK0Qm0yAStrQocs5Yk/p2P4c6WtZsGKKNc1pPFo7Nndt2ESIRDUeOcNCel/0FM\n" +
//                "TIMml3GSeYCNyeWDA1BWeHr0EpG5pUphHitFMFY4DtmAmLM5dh7mQz1tkQwYzwjk\n" +
//                "/XPtdwFRa21gGLuieL/GNiPAFWw1hj3yUI0rTz1+4AyVI+QgjoQrgMUS5xDld6ND\n" +
//                "UT1KiwiodIqvzWMqaow5MpLmQqDPSU85RZxPSYjUTbX5jN6V0FMZgD1M\n" +
//                "=82Dh\n" +
//                "-----END PGP PUBLIC KEY BLOCK-----\n";
//    }
}
