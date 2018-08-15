package com.liviridi.rest.exception;

public class UnexecutableException extends Exception {

    /**
     * serialVersionUID
     */
    private static final long serialVersionUID = -3062691949926103865L;

    public UnexecutableException() {
        super();
    }

    public UnexecutableException(String message) {
        super(message);
    }

    public UnexecutableException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnexecutableException(Throwable cause) {
        super(cause);
    }

    protected UnexecutableException(String message, Throwable cause,
                        boolean enableSuppression,
                        boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
