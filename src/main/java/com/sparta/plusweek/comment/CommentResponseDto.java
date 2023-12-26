package com.sparta.plusweek.comment;

import com.sparta.plusweek.CommonResponseDto;
import com.sparta.plusweek.user.UserResponseDto;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class CommentResponseDto extends CommonResponseDto {
    private Long id;
    private String text;
    private UserResponseDto user;
    private LocalDateTime createDate;

    public CommentResponseDto(Comment comment) {
        this.id = comment.getId();
        this.text = comment.getText();
        this.user = new UserResponseDto(comment.getUser());
        this.createDate = comment.getCreateDate();
    }
}