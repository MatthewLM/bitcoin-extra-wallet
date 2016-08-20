package com.netki.exceptions;

public class WalletNameLookupException extends Exception {

	private static final long serialVersionUID = 6781745266624656079L;

    public WalletNameLookupException() {super(); }

	public WalletNameLookupException(String message) {
        super(message);
    }

    public WalletNameLookupException(String message, Throwable throwable) {
        super(message, throwable);
    }
}