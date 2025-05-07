package com.tailtales.backend.domain.member.service;

import com.tailtales.backend.domain.member.dto.AdminInsertRequestDto;
import com.tailtales.backend.domain.member.dto.AdminResponseDto;
import com.tailtales.backend.domain.member.dto.AdminUpdateRequestDto;

public interface MemberService {

    void insertAdmin(AdminInsertRequestDto dto);

    AdminResponseDto getAdminInfo(String id);

    void updateAdminInfo(String id, AdminUpdateRequestDto dto);

    void deleteAdmin(String id);

}
