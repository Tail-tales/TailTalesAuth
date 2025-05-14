package com.tailtales.backend.domain.member.repository;

import com.tailtales.backend.domain.member.entity.Member;
import com.tailtales.backend.domain.member.entity.MemberRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Integer> {

    // 아이디 중복 체크
    @Query("SELECT COUNT(m) > 0 FROM Member m WHERE m.id = :id")
    boolean existsById(@Param("id") String id);

    // 이메일 중복 체크
    @Query("SELECT COUNT(m) > 0 FROM Member m WHERE m.email = :email")
    boolean existsByEmail(@Param("email") String email);

    // 아이디 조회 (모든 회원)
    @Query("SELECT m FROM Member m WHERE m.id = :id AND m.isDeleted = false")
    Optional<Member> findById(String id);

    // 아이디 조회 (관리자)
    @Query("SELECT m FROM Member m WHERE m.id = :id AND m.role = :adminRole AND m.isDeleted = false")
    Optional<Member> findById(@Param("id") String id, @Param("adminRole") MemberRole adminRole);

    // refresh token 검증
    @Query("SELECT m FROM Member m WHERE m.refreshToken = :refreshToken AND m.isDeleted = false")
    Optional<Member> findByRefreshToken(@Param("refreshToken") String refreshToken);

    // 아이디 조회 (사용자)
    @Query("SELECT m FROM Member m WHERE m.provider = :provider AND m.providerId = :providerId AND m.isDeleted = false")
    Optional<Member> findByProviderAndProviderId(@Param("provider") String provider, @Param("providerId") String providerId);

    // 이메일 조회 (사용자)
    @Query("SELECT m FROM Member m WHERE m.isDeleted = false")
    Optional<Member> findByEmail(String email);

    // providerId로 조회 (소셜 로그인 사용자)
    @Query("SELECT m FROM Member m WHERE m.providerId = :providerId AND m.isDeleted = false")
    Optional<Member> findByProviderId(String providerId);

}
