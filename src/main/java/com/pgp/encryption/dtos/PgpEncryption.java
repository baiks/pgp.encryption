package com.pgp.encryption.dtos;

import lombok.*;


@Getter
@Setter
public class PgpEncryption {
    private String privatekey;
    private String content;
    private String passphrase;

}
 