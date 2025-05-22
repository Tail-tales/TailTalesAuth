package com.tailtales.backend.common.exception;

import com.tailtales.backend.common.enumType.ErrorCode;
import lombok.Getter;

@Getter
public class CustomException extends RuntimeException {

    private final ErrorCode errorCode;

    public CustomException(ErrorCode errorCode) {

        super(errorCode.getMessage());
        this.errorCode = errorCode;

    }

}
