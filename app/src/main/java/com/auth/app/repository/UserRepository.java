package com.auth.app.repository;

import com.auth.app.DTO.UserEmailIdDTO;
import com.auth.app.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User,String> {
    Optional<User> findByEmail(String email);
    Optional<User> findByResetToken(String resetToken);
    @Query(value = "{}", fields = "{'id': 1, 'email': 1}")
    List<UserEmailIdDTO> findAllUserEmailsAndIds();
}
