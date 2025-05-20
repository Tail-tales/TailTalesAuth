package com.tailtales.backend.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED) // 이 어노테이션은 Spring Web MVC에서 주로 사용되지만, 명시적 의미를 위해 남겨둘 수 있습니다. WebFlux에서는 @ControllerAdvice가 더 중요합니다.
public class UnauthorizedException extends RuntimeException {
    public UnauthorizedException(String message) {
        super(message);
    }

    public UnauthorizedException(String message, Throwable cause) {
        super(message, cause);
    }
}
