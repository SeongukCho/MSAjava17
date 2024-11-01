package kopo.poly.repository;

import kopo.poly.repository.entity.UserInfoEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserInfoRepository extends JpaRepository<UserInfoEntity, Long> {

    /**
     * 회원 존재 여부 체크
     * java.util.Optional 객체는 자바의 NullPointer 에러에 대응하기 위해 1.8 버전부터 추가된 자바 객체
     * 객체에 값이 존재하는지 체크할 때 활용 가능함
     * 쿼리 예 : SELECT * FROM USER_INFO WHERE USER_ID = 'hglee67'
     */
    Optional<UserInfoEntity> findByUserId(String userId);
}
