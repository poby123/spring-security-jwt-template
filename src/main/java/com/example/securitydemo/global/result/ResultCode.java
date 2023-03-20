package com.example.securitydemo.global.result;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * ResultCode Convention
 * - 도메인 별로 나누어 관리
 * - [동사_목적어_SUCCESS] 형태로 생성
 * - 코드는 도메인명 앞에서부터 1~2글자로 사용
 * - 메시지는 "~~다."로 마무리
 */
@Getter
@AllArgsConstructor
public enum ResultCode {

    // Member
    REGISTER_SUCCESS(200, "M001", "회원가입에 성공하였습니다."),
    LOGIN_SUCCESS(200, "M002", "로그인에 성공하였습니다."),
    REISSUE_SUCCESS(200, "M003", "재발급에 성공하였습니다."),
    GET_USERPROFILE_SUCCESS(200, "M004", "회원 프로필을 조회하였습니다."),
    GET_MINIPROFILE_SUCCESS(200, "M005", "미니 프로필을 조회하였습니다."),
    UPLOAD_MEMBER_IMAGE_SUCCESS(200, "M006", "회원 이미지를 등록하였습니다."),
    DELETE_MEMBER_IMAGE_SUCCESS(200, "M007", "회원 이미지를 삭제하였습니다."),
    GET_EDIT_PROFILE_SUCCESS(200, "M008", "회원 프로필 수정정보를 조회하였습니다."),
    EDIT_PROFILE_SUCCESS(200, "M009", "회원 프로필을 수정하였습니다."),
    UPDATE_PASSWORD_SUCCESS(200, "M010", "회원 비밀번호를 변경하였습니다."),
    CHECK_USERNAME_GOOD(200, "M011", "사용가능한 username 입니다."),
    CHECK_USERNAME_BAD(200, "M012", "사용불가능한 username 입니다."),
    CONFIRM_EMAIL_FAIL(200, "M013", "이메일 인증을 완료할 수 없습니다."),
    SEND_CONFIRM_EMAIL_SUCCESS(200, "M014", "인증코드 이메일을 전송하였습니다."), // 결번 M015
    GET_MENU_MEMBER_SUCCESS(200, "M016", "상단 메뉴 프로필을 조회하였습니다."),
    SEND_RESET_PASSWORD_EMAIL_SUCCESS(200, "M017", "비밀번호 재설정 메일을 전송했습니다."),
    RESET_PASSWORD_SUCCESS(200, "M018", "비밀번호 재설정에 성공했습니다."),
    LOGIN_WITH_CODE_SUCCESS(200, "M019", "비밀번호 재설정 코드로 로그인 했습니다."),
    LOGOUT_SUCCESS(200, "M020", "로그아웃하였습니다."),
    CHECK_RESET_PASSWORD_CODE_GOOD(200, "M021", "올바른 비밀번호 재설정 코드입니다."),
    CHECK_RESET_PASSWORD_CODE_BAD(200, "M022", "올바르지 않은 비밀번호 재설정 코드입니다."),
    LOGOUT_BY_ANOTHER_DEVICE(200, "M023", "다른 기기에 의해 로그아웃되었습니다."),
    GET_LOGIN_DEVICES_SUCCESS(200, "M024", "로그인 한 기기들을 조회하였습니다."),
    LOGOUT_DEVICE_SUCCESS(200, "M025", "해당 기기를 로그아웃 시켰습니다.");

    private final int status;
    private final String code;
    private final String message;

}
