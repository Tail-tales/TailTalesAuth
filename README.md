## TailTalesAuth 🔐

본 문서는 MSA (Microservices Architecture) 환경에서 사용자 인증 및 권한 부여를 담당하는 인증 서버 (`TailTalesAuth`)에 대한 간략한 설명을 담고 있습니다.

---

### 🚀 기술 스택

* **Java 17**
* **Spring Boot 3.4.4**
* **Spring Security**
* **Spring Web**
* **Spring Data JPA**
* **OAuth2 Client**
* **jjwt (JSON Web Token)**
* **MariaDB**

---

### 🔧 개발 예정 기능

* **일반 로그인:** 아이디/비밀번호 기반 사용자 인증 및 JWT (JSON Web Token) 발급
* **소셜 로그인:** 외부 소셜 플랫폼 (예: Google, Kakao 등) 연동을 통한 사용자 인증 및 JWT 발급
* **JWT 발급 및 갱신:** 인증 성공 시 접근 토큰 및 갱신 토큰 발급
* **JWT 검증:** API 요청 시 전달된 JWT를 검증하여 사용자 인증 및 권한 정보 확인
* **역할 기반 권한 부여:** 사용자의 역할에 따라 API 접근 권한 관리