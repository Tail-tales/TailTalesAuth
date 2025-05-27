package com.tailtales.backend.domain.member.service;

import com.tailtales.backend.domain.member.dto.AdminInsertRequestDto;
import com.tailtales.backend.domain.member.dto.AdminResponseDto;
import com.tailtales.backend.domain.member.dto.AdminUpdateRequestDto;
import com.tailtales.backend.domain.member.dto.UserResponseDto;

import java.util.List;
import java.util.Optional;

public interface MemberService {

    void insertAdmin(AdminInsertRequestDto dto);

    AdminResponseDto getAdminInfo(String id);

    void updateAdminInfo(String id, AdminUpdateRequestDto dto);

    void deleteAdmin(String id);

    List<UserResponseDto> getUsers();

    Optional<UserResponseDto> getUserInfo(String provider, String providerId);

    void deleteUser(String provider, String providerId);

}
