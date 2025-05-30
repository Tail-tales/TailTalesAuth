package com.tailtales.backend.error.exception;

import com.tailtales.backend.error.enumType.ErrorCode;
import lombok.Getter;

@Getter
public class CustomException extends RuntimeException {

    private final ErrorCode errorCode;

    public CustomException(ErrorCode errorCode) {

        super(errorCode.getMessage());
        this.errorCode = errorCode;

    }

}
