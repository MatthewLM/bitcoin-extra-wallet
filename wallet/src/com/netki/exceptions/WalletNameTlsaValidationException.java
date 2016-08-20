package com.netki.exceptions;

public class WalletNameTlsaValidationException extends WalletNameLookupException {

    public WalletNameTlsaValidationException() {
        super();
    }

    public WalletNameTlsaValidationException(String message) {
        super(message);
    }

    public WalletNameTlsaValidationException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
