package com.tailtales.backend.batch.member.config;

import com.tailtales.backend.batch.member.reader.MemberItemReader;
import com.tailtales.backend.batch.member.writer.MemberItemWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.Step;
import org.springframework.batch.core.job.builder.JobBuilder;
import org.springframework.batch.core.repository.JobRepository;
import org.springframework.batch.core.step.builder.StepBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.transaction.PlatformTransactionManager;

@Configuration
@RequiredArgsConstructor
public class MemberCleanupJobConfig {

    private final MemberItemReader reader;
    private final MemberItemWriter writer;

    @Bean
    public Job deleteOldMembersJob(JobRepository jobRepository, Step deleteStep) {
        return new JobBuilder("deleteOldMembersJob", jobRepository)
                .start(deleteStep)
                .build();
    }

    @Bean
    public Step deleteStep(JobRepository jobRepository, PlatformTransactionManager transactionManager) {
        return new StepBuilder("deleteOldMembersStep", jobRepository)
                .<Integer, Integer>chunk(100, transactionManager)
                .reader(reader)
                .writer(writer)
                .build();
    }

}
