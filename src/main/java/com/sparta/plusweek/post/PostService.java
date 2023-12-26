package com.sparta.plusweek.post;

import com.sparta.plusweek.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.RejectedExecutionException;

@Service
@RequiredArgsConstructor
public class PostService {

    private final PostRepository postRepository;

    public PostResponseDto createPost(PostRequestDto postRequestDto, User user) {
        Post post = new Post(postRequestDto);
        post.setUser(user);

        Post saved = postRepository.save(post);

        return new PostResponseDto(saved);
    }


    public PostResponseDto getPostDto(Long postId) {
        Post post = getPost(postId);
        return new PostResponseDto(post);
    }

    @Transactional
    public PostResponseDto updatePost(Long postId, PostRequestDto postRequestDto, User user) {
        Post post = getUserPost(postId, user);

        post.setTitle(postRequestDto.getTitle());
        post.setContent(postRequestDto.getContent());

        return new PostResponseDto(post);
    }

    public void deletePost(Long postId) {
        postRepository.findById(postId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않습니다."));

        postRepository.deleteById(postId);
    }

    @Transactional
    @EntityGraph(attributePaths = "comments")
    public Post getPost(Long postId) {
        return postRepository.findById(postId)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않습니다."));
    }

    public Post getUserPost(Long postId, User user) {
        Post post = getPost(postId);

        if (!user.getId().equals(post.getUser().getId())) {
            throw new RejectedExecutionException("작성자만 작성가능합니다.");
        }
        return post;
    }
}