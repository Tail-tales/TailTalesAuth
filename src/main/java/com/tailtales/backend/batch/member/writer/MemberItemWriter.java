package com.tailtales.backend.batch.member.writer;

import com.tailtales.backend.domain.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.batch.item.Chunk;
import org.springframework.batch.item.ItemWriter;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class MemberItemWriter implements ItemWriter<Integer> {

    private final MemberRepository memberRepository;

    @Override
    public void write(Chunk<? extends Integer> chunk) {
        memberRepository.deleteAllByIdInBatch( (List<Integer>) chunk.getItems());
    }

}
