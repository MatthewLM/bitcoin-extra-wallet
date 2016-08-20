package com.netki.exceptions;

public class WalletNameURLFailedException extends WalletNameLookupException {

    public WalletNameURLFailedException() {
        super();
    }

    public WalletNameURLFailedException(String message) {
        super(message);
    }

    public WalletNameURLFailedException(String message, Throwable throwable) {
        super(message, throwable);
    }
}
