package com.tailtales.backend.auth.service;

import lombok.extern.log4j.Log4j2;
import org.springframework.mail.MailException;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.stereotype.Service;

@Log4j2
@Service
public class SimpleMailMessageService {

    private final MailSender mailSender;

    public SimpleMailMessageService(MailSender mailSender) {
        this.mailSender = mailSender;
    }

    public void sendEmail(String email, String title, String content) {

        SimpleMailMessage msg = new SimpleMailMessage();

        // 받는 사람 이메일
        msg.setTo(email);
        // 이메일 제목
        msg.setSubject(title);
        // 이메일 내용
        msg.setText(content);

        try {
            // 메일 보내기
            this.mailSender.send(msg);
            System.out.println("이메일 전송 성공!");
        } catch (MailException error) {
            log.error(error);
        }
    }

}
