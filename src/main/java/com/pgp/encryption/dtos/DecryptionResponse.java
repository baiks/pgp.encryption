package com.pgp.encryption.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DecryptionResponse {
    private String decryptedContent;
}
 