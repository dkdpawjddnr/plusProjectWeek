package com.sparta.plusweek.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

@Service
@RequiredArgsConstructor
public class UserService {
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public void signup(UserRequestDto userRequestDto) {
        String username = userRequestDto.getUsername();
        String password = passwordEncoder.encode(userRequestDto.getPassword());

        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException("username이 이미 존재합니다.");
        }

        if (isPasswordValid(userRequestDto)) {
            throw new IllegalArgumentException("비밀번호에 username을 포함할 수 업습니다.");
        }

        if (!isPasswordConfirmed(userRequestDto)) {
            throw new IllegalArgumentException("비밀번호가 다릅니다.");
        }

        User user = new User(username, password);
        userRepository.save(user);

    }

    public void login(UserRequestDto userRequestDto) {
        String username = userRequestDto.getUsername();
        String password = userRequestDto.getPassword();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 User입니다."));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new IllegalArgumentException("비밀번호가 다릅니다.");
        }
    }

    public boolean isPasswordValid(UserRequestDto userRequestDto) {
        return userRequestDto.getPassword().contains(userRequestDto.getUsername());
    }

    // 비밀번호 확인과 검도
    public boolean isPasswordConfirmed(UserRequestDto userRequestDto) {
        return userRequestDto.getPassword().equals(userRequestDto.getConfirmPassword());
    }
}