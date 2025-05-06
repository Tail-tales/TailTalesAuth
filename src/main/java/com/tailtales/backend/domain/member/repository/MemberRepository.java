package com.tailtales.backend.domain.member.repository;

import com.tailtales.backend.domain.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Integer> {

    // 아이디 중복 체크
    @Query("SELECT COUNT(m) > 0 FROM Member m WHERE m.id = :id AND m.isDeleted = false")
    boolean existsById(@Param("id") String id);

    // 이메일 중복 체크
    @Query("SELECT COUNT(m) > 0 FROM Member m WHERE m.email = :email AND m.isDeleted = false")
    boolean existsByEmail(@Param("email") String email);

    // 아이디 조회
    @Query("SELECT m FROM Member m WHERE m.id = :id AND m.isDeleted = false")
    Optional<Member> findById(@Param("id") String id);

    // refresh token 검증
    @Query("SELECT m FROM Member m WHERE m.refreshToken = :refreshToken AND m.isDeleted = false")
    Optional<Member> findByRefreshToken(@Param("refreshToken") String refreshToken);

}
