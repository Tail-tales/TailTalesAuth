package com.tailtales.backend.domain.member.controller;

import com.tailtales.backend.common.enumType.ErrorCode;
import com.tailtales.backend.common.exception.CustomException;
import com.tailtales.backend.domain.member.dto.AdminInsertRequestDto;
import com.tailtales.backend.domain.member.dto.AdminResponseDto;
import com.tailtales.backend.domain.member.dto.AdminUpdateRequestDto;
import com.tailtales.backend.domain.member.dto.UserResponseDto;
import com.tailtales.backend.domain.member.service.MemberService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

import static com.tailtales.backend.common.constants.ApiConstants.*;

@Log4j2
@RestController
@RequestMapping(ADMIN_BASE_URL)
@RequiredArgsConstructor
@Tag(name = "Member", description = "Member API")
public class AdminController {

    private final MemberService memberService;

    // 관리자 회원가입
    @PostMapping
    public ResponseEntity<String> insertAdmin(@RequestBody @Valid AdminInsertRequestDto adminInsertRequestDto) {

        memberService.insertAdmin(adminInsertRequestDto);
        return ResponseEntity.ok("관리자 등록이 완료되었습니다.");

    }

    // 관리자 정보 조회(자신의 정보만 조회 가능)
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<AdminResponseDto> getAdminInfo(@PathVariable(name = "id") String id,
                                                         @AuthenticationPrincipal UserDetails userDetails) {

        String loggedInAdminId = userDetails.getUsername();
        if (!loggedInAdminId.equals(id)) {
            throw new CustomException(ErrorCode.ACCESS_DENIED);
        }

        AdminResponseDto adminResponseDto = memberService.getAdminInfo(id);
        return ResponseEntity.ok(adminResponseDto);

    }

    // 관리자 개인 정보 수정
    @PatchMapping("/me")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> updateAdmin(@RequestBody @Valid AdminUpdateRequestDto adminUpdateRequestDto,
                                              @AuthenticationPrincipal UserDetails userDetails) {

        String id = userDetails.getUsername();
        memberService.updateAdminInfo(id, adminUpdateRequestDto);
        return ResponseEntity.ok("관리자 정보 수정이 완료되었습니다.");

    }

    // 관리자 계정 삭제
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deleteAdmin(@PathVariable(name = "id") String id) {

        memberService.deleteAdmin(id);
        return ResponseEntity.ok("관리자 계정이 삭제되었습니다.");

    }

    // 전체 사용자 조회
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<UserResponseDto>> getUsers(@AuthenticationPrincipal UserDetails userDetails) {
        String memberId = userDetails.getUsername();
        log.info("memberId: {}", memberId);
        List<UserResponseDto> users = memberService.getUsers();
        return ResponseEntity.ok(users);
    }

    // 개별 사용자 조회
    @GetMapping("/users/{provider}/{providerId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<UserResponseDto> getUserInfo(@PathVariable String provider, // Optional 제거
                                                       @PathVariable String providerId,
                                                       @AuthenticationPrincipal UserDetails userDetails) {

        String id = userDetails.getUsername();
        log.info("memberId: {}", id);

        Optional<UserResponseDto> userInfoOptional = memberService.getUserInfo(provider, providerId);

        return ResponseEntity.ok(userInfoOptional.get());
    }

    // 유저 계정 삭제
    @DeleteMapping("/users/{provider}/{providerId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deleteUser(@PathVariable String provider,
                                           @PathVariable String providerId,
                                           @AuthenticationPrincipal UserDetails userDetails) {

        String id = userDetails.getUsername();
        log.info("memberId: {}", id);

        memberService.deleteUser(provider, providerId);
        return ResponseEntity.ok("관리자 계정이 삭제되었습니다.");

    }

}
