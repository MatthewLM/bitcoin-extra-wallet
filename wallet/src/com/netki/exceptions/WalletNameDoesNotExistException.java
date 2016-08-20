package com.netki.exceptions;

public class WalletNameDoesNotExistException extends WalletNameLookupException {

    public WalletNameDoesNotExistException() {
        super();
    }

    public WalletNameDoesNotExistException(String message) {
        super(message);
    }

    public WalletNameDoesNotExistException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
