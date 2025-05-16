package com.tailtales.backend.domain.member.controller;

import com.tailtales.backend.domain.member.dto.AdminInsertRequestDto;
import com.tailtales.backend.domain.member.dto.AdminResponseDto;
import com.tailtales.backend.domain.member.dto.AdminUpdateRequestDto;
import com.tailtales.backend.domain.member.dto.UserResponseDto;
import com.tailtales.backend.domain.member.service.MemberService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Log4j2
@RestController
@RequestMapping("/api/members")
@RequiredArgsConstructor
@Tag(name = "Member", description = "Member API")
public class MemberController {

    private final MemberService memberService;

    // 관리자 회원가입
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
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
            return new ResponseEntity<>(HttpStatus.FORBIDDEN); // 접근 거부 (403 Forbidden)
        }

        AdminResponseDto adminResponseDto = memberService.getAdminInfo(id);
        return ResponseEntity.ok(adminResponseDto);

    }

    // 관리자 개인 정보 수정
    @PutMapping("/me")
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

}
