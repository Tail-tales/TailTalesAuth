package com.tailtales.backend.domain.member.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;

import java.time.LocalDateTime;

@Entity
@Getter
@Builder(toBuilder = true)
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "Member")
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int mno;

    @Column(unique = true, length = 50)
    private String id;

    @Column(length = 100)
    private String password;

    private String provider;

    @Column(name = "provider_id")
    private String providerId;

    @Column(unique = true, length = 100)
    private String email;

    @Column(length = 50)
    private String name;

    @Column(length = 20)
    private String contact;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    private MemberLevel level = MemberLevel.Bear;

    @Enumerated(EnumType.STRING)
    private MemberRole role;

    @Column(name = "img_url")
    private String imgUrl;

    @CreatedDate
    @Builder.Default
    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "is_deleted")
    @Builder.Default
    private boolean isDeleted = false;

    @Column(name = "refresh_token")
    private String refreshToken;

}
