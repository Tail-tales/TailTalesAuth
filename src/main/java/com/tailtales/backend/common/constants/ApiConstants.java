package com.tailtales.backend.common.constants;

public class ApiConstants {

    public static final String ERROR_URL = "/error";

    public static final String ADMIN_BASE_URL = "/api/admin";
    public static final String ADMIN_AUTH_BASE_URL = ADMIN_BASE_URL + "/auth";

    public static final String ADMIN_REGISTER = ADMIN_BASE_URL;
    public static final String ADMIN_INFO = ADMIN_BASE_URL + "/{id}";
    public static final String ADMIN_UPDATE = ADMIN_BASE_URL + "/me";
    public static final String ADMIN_DELETE = ADMIN_BASE_URL + "/{id}";

    public static final String ADMIN_VERIFY_TOKEN = ADMIN_AUTH_BASE_URL + "/verify";
    public static final String ADMIN_CHECK_ID = ADMIN_AUTH_BASE_URL + "/exists/id/{id}";
    public static final String ADMIN_CHECK_EMAIL = ADMIN_AUTH_BASE_URL + "/exists/email/{email}";
    public static final String ADMIN_LOGIN = ADMIN_AUTH_BASE_URL + "/login";
    public static final String ADMIN_LOGOUT = ADMIN_AUTH_BASE_URL + "/logout";
    public static final String ADMIN_TOKEN_REFRESH = ADMIN_AUTH_BASE_URL + "/refresh";
    public static final String ADMIN_FIND_PASSWORD = ADMIN_AUTH_BASE_URL + "/findPassword";

    public static final String ADMIN_USERS_INFO = ADMIN_BASE_URL + "/users";
    public static final String ADMIN_USER_INFO = ADMIN_BASE_URL + "/users/{provider}/{providerId}";
    public static final String ADMIN_DELETE_USER = ADMIN_BASE_URL + "/users/{provider}/{providerId}";


    public static final String USER_BASE_URL = "/api/user";
    public static final String USER_AUTH_BASE_URL = USER_BASE_URL + "/auth";

    public static final String USER_LOGIN = "/oauth2";
    public static final String USER_LOGIN_CALLBACK = "/login/oauth2/code";

}
