package com.tailtales.backend.batch.member.scheduler;

import lombok.RequiredArgsConstructor;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.JobParameters;
import org.springframework.batch.core.JobParametersBuilder;
import org.springframework.batch.core.launch.JobLauncher;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class MemberBatchScheduler {

    private final JobLauncher jobLauncher;
    private final Job deleteOldMembersJob;

    @Scheduled(cron = "0 0 1 * * ?") // 매일 새벽 1시
    public void runJob() throws Exception {
        JobParameters params = new JobParametersBuilder()
                .addLong("time", System.currentTimeMillis())
                .toJobParameters();
        jobLauncher.run(deleteOldMembersJob, params);
    }

}
