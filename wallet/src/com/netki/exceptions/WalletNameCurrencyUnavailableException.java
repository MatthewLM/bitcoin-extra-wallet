package com.netki.exceptions;

public class WalletNameCurrencyUnavailableException extends WalletNameLookupException {

    public WalletNameCurrencyUnavailableException() {
        super();
    }

    public WalletNameCurrencyUnavailableException(String message) {
        super(message);
    }

    public WalletNameCurrencyUnavailableException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
