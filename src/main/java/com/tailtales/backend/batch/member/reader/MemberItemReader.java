package com.tailtales.backend.batch.member.reader;

import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.springframework.batch.item.ItemReader;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

@Component
@RequiredArgsConstructor
public class MemberItemReader implements ItemReader<Integer> {

    private final EntityManager em;

    private List<Integer> memberIdsToDelete;
    private int index = 0;

    @Override
    public Integer read() {
        if (memberIdsToDelete == null) {
            memberIdsToDelete = em.createQuery("""
                SELECT m.mno FROM Member m 
                WHERE m.isDeleted = true AND m.deletedAt < :threshold
                """, Integer.class)
                    .setParameter("threshold", LocalDateTime.now().minusDays(30))
                    .getResultList();
        }

        if (index < memberIdsToDelete.size()) {
            return memberIdsToDelete.get(index++);
        } else {
            return null;
        }
    }

}
