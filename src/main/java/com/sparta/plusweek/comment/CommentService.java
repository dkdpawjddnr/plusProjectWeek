package com.sparta.plusweek.comment;

import com.sparta.plusweek.post.Post;
import com.sparta.plusweek.post.PostService;
import com.sparta.plusweek.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.RejectedExecutionException;

@Service
@RequiredArgsConstructor
public class CommentService {

    private final CommentRepository commentRepository;

    private final PostService postService;

    public CommentResponseDto createComment(CommentRequestDto commentRequestDto, User user) {
        Post post = postService.getPost(commentRequestDto.getPostId());

        Comment comment = new Comment(commentRequestDto);
        comment.setUser(user);
        comment.setPost(post);

        commentRepository.save(comment);

        return new CommentResponseDto(comment);
    }

    @Transactional
    public CommentResponseDto updateComment(Long commentId, CommentRequestDto commentRequestDto, User user) {
        Comment comment = getUserComment(commentId, user);

        comment.setText(commentRequestDto.getText());

        return new CommentResponseDto(comment);
    }

    private Comment getUserComment(Long commentId, User user) {
        Comment comment = commentRepository.findById(commentId)
                .orElseThrow(() -> new IllegalArgumentException("This comment is not exist."));

        if(!user.getId().equals(comment.getUser().getId())) {
            throw new RejectedExecutionException("Only authors can modify it.");
        }
        return comment;
    }

    public void deleteComment(Long commentId, User user) {
        Comment comment = getUserComment(commentId, user);

        commentRepository.delete(comment);
    }
}
