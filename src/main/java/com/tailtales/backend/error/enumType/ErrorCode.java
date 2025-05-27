package com.tailtales.backend.error.enumType;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {

    // ⛔️ 일반 유효성 검사
    INVALID_INPUT_VALUE("V001", "입력 값이 유효하지 않습니다.", HttpStatus.BAD_REQUEST),

    // 🔐 권한
    ACCESS_DENIED("A001", "접근이 거부되었습니다.", HttpStatus.FORBIDDEN),
    UNAUTHORIZED("A002", "인증 정보가 없습니다.", HttpStatus.UNAUTHORIZED),

    // 🔓 로그인
    USERNAME_NOT_FOUND("L001", "존재하지 않는 아이디입니다.", HttpStatus.NOT_FOUND),
    INVALID_CREDENTIALS("L002", "아이디 또는 비밀번호가 올바르지 않습니다.", HttpStatus.UNAUTHORIZED),

    // 🔄 리프레시 토큰
    REFRESH_TOKEN_EXPIRED("RT001", "리프레시 토큰이 만료되었습니다.", HttpStatus.UNAUTHORIZED),
    INVALID_REFRESH_TOKEN("RT002", "유효하지 않은 리프레시 토큰입니다.", HttpStatus.UNAUTHORIZED),

    // 🔐 액세스 토큰 관련
    ACCESS_TOKEN_EXPIRED("AT001", "액세스 토큰이 만료되었습니다.", HttpStatus.UNAUTHORIZED),
    INVALID_ACCESS_TOKEN("AT002", "유효하지 않은 액세스 토큰입니다.", HttpStatus.UNAUTHORIZED),
    MALFORMED_ACCESS_TOKEN("AT003", "형식이 잘못된 액세스 토큰입니다.", HttpStatus.UNAUTHORIZED),
    UNSUPPORTED_ACCESS_TOKEN("AT004", "지원하지 않는 형식의 액세스 토큰입니다.", HttpStatus.UNAUTHORIZED),
    EMPTY_ACCESS_TOKEN("AT005", "액세스 토큰이 비어 있습니다.", HttpStatus.UNAUTHORIZED),

    // ✅ 중복 체크
    DUPLICATE_USERNAME("C001", "이미 존재하는 아이디입니다.", HttpStatus.CONFLICT),
    DUPLICATE_EMAIL("C002", "이미 존재하는 이메일입니다.", HttpStatus.CONFLICT),

    // 🛠 개인정보 수정
    NULL_VALUE("U001", "입력값이 누락되었습니다.", HttpStatus.BAD_REQUEST),
    USERNAME_IN_USE("U002", "이미 사용 중인 아이디입니다.", HttpStatus.CONFLICT),
    EMAIL_IN_USE("U003", "이미 사용 중인 이메일입니다.", HttpStatus.CONFLICT),
    INVALID_PASSWORD_FORMAT("U004", "비밀번호 형식이 올바르지 않습니다.", HttpStatus.BAD_REQUEST),

    // 🧾 회원가입
    DELETED_ACCOUNT("J001", "삭제된 계정입니다.", HttpStatus.CONFLICT),
    INVALID_SIGNUP_FORMAT("J002", "아이디, 비밀번호 또는 이메일 형식이 올바르지 않습니다.", HttpStatus.BAD_REQUEST),

    // 👤 유저 조회/삭제
    PROVIDER_MISMATCH("U101", "provider 값이 일치하지 않습니다.", HttpStatus.BAD_REQUEST),
    PROVIDER_ID_MISMATCH("U102", "providerId 값이 일치하지 않습니다.", HttpStatus.BAD_REQUEST),
    PROVIDER_OR_ID_MISMATCH("U103", "provider 혹은 providerId 값이 일치하지 않습니다.", HttpStatus.BAD_REQUEST),
    ALREADY_DEACTIVATED_USER("U104", "이미 탈퇴된 계정입니다.", HttpStatus.CONFLICT),

    // 📄 게시글 처리
    POST_NULL_VALUE("P001", "게시글 내용이 비어 있습니다.", HttpStatus.BAD_REQUEST),
    POST_TOO_LONG("P002", "게시글 내용이 너무 깁니다.", HttpStatus.BAD_REQUEST),
    POST_CATEGORY_NOT_FOUND("P003", "해당 카테고리가 존재하지 않습니다.", HttpStatus.NOT_FOUND),
    FILE_SIZE_EXCEEDED("P004", "첨부파일 크기 제한을 초과했습니다.", HttpStatus.PAYLOAD_TOO_LARGE),
    UNSUPPORTED_FILE_TYPE("P005", "지원하지 않는 파일 형식입니다.", HttpStatus.UNSUPPORTED_MEDIA_TYPE),
    POST_NOT_FOUND("P006", "해당 게시글이 존재하지 않습니다.", HttpStatus.NOT_FOUND),
    EMPTY_CATEGORY_POSTS("P007", "해당 카테고리에 게시글이 없습니다.", HttpStatus.NOT_FOUND),

    // 📁 카테고리 처리
    DUPLICATE_CATEGORY("CA001", "이미 존재하는 카테고리입니다.", HttpStatus.CONFLICT),
    INVALID_CATEGORY_NAME("CA002", "카테고리 이름이 유효하지 않습니다.", HttpStatus.BAD_REQUEST),
    CATEGORY_CONTAINS_POSTS("CA003", "하위 게시글이 존재하는 카테고리는 삭제할 수 없습니다.", HttpStatus.CONFLICT),
    CATEGORY_NOT_FOUND("CA004", "카테고리가 존재하지 않습니다.", HttpStatus.NOT_FOUND),
    NOT_SUPPORTED_METHOD("CA005", "지원하지 않는 작업 유형입니다.", HttpStatus.BAD_REQUEST),
    CATEGORY_FILED_REQUIRED("CA006", "게시글 카테고리는 필수입니다.", HttpStatus.BAD_REQUEST),

    // 🛠 서버
    INTERNAL_SERVER_ERROR("S001", "서버 내부 오류가 발생했습니다.", HttpStatus.INTERNAL_SERVER_ERROR),
    UNKNOWN("S002", "알 수 없는 에러가 발생했습니다.", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String code;
    private final String message;
    private final HttpStatus status;

    ErrorCode(String code, String message, HttpStatus status) {
        this.code = code;
        this.message = message;
        this.status = status;
    }

}
