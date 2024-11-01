package kopo.poly.service.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import kopo.poly.auth.AuthInfo;
import kopo.poly.dto.UserInfoDTO;
import kopo.poly.repository.UserInfoRepository;
import kopo.poly.repository.entity.UserInfoEntity;
import kopo.poly.service.IUserInfoSsService;
import kopo.poly.util.CmmUtil;
import kopo.poly.util.DateUtil;
import kopo.poly.util.EncryptUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserInfoSsService implements IUserInfoSsService {

    /**
     * RequiredArgsConstructor 어노테이션으로 생성자를 자동 생성함
     * userInfoRepository 변수에 이미 메모리에 올라간 UserInfoRepository 객체를 넣어줌
     * 예전에는 autowired 어노테이션을 통해 설정했었지만, 이젠 생성자를 통해 객체 주입함
     */
    private final UserInfoRepository userInfoRepository;

    /**
     * Spring Security 에서 로그인 처리를 하기 위해 실행하는 함수
     * Spring Security 의 인증 기능을 사용하기 위해선 반드시 만들어야 하는 함수
     * <p>
     * Controller 로부터 호출되지 않고 , Spring Security 가 바로 호출함
     * <p>
     * 아이디로 검색하고, 검색한 결과를 기반으로 Spring Security 가 비밀번호가 같은지 판단함
     * <p>
     * 아이디와 패스워드가 일치하지 않으면, 자동으로 UsernameNotFoundException 발생시킴
     *
     * @param userId 사용자 아이디
     */
    @Override
    public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {

        log.info(this.getClass().getName() + ".loadUserByUsername Start!");

        /**
         * 로그인 요청한 사용자 아이디를 검색함
         * SELECT * FROM USER_INFO WHERE USER_ID = 'hglee67'
         */
        UserInfoEntity rEntity = userInfoRepository.findByUserId(userId)
                .orElseThrow(() -> new UsernameNotFoundException(userId + " Not Found User"));

        // rEntity 데이터를 DTO 로 변환하기
        UserInfoDTO rDTO = new ObjectMapper().convertValue(rEntity, UserInfoDTO.class);

        // 비밀번호가 맞는지 체크 및 권한 부여를 위해 rDTO 를 UserDetails 를 구현한 AuthInfo 에 넣어주기
        return new AuthInfo(rDTO);
    }

    @Override
    public int insertUserInfo(UserInfoDTO pDTO) {

        log.info(this.getClass().getName() + ".insertUserInfo Start!");

        int res = 0; // 회원가입 성공 : 1, 아이디 중복으로인한 가입 취소 : 2, 기타 에러 발생 : 0

        String userId = CmmUtil.nvl(pDTO.userId());
        String userName = CmmUtil.nvl(pDTO.userName());
        String password = CmmUtil.nvl(pDTO.password());
        String email = CmmUtil.nvl(pDTO.email());
        String addr1 = CmmUtil.nvl(pDTO.addr1());
        String addr2 = CmmUtil.nvl(pDTO.addr2());
        String roles = CmmUtil.nvl(pDTO.roles());

        log.info("userId : " + userId);
        log.info("userName : " + userName);
        log.info("password : " + password);
        log.info("email : " + email);
        log.info("addr1 : " + addr1);
        log.info("addr2 : " + addr2);
        log.info("roles : " + roles);

        // 회원 중복 가입 방지를 위해 DB 에서 데이터 조회
        Optional<UserInfoEntity> rEntity = userInfoRepository.findByUserId(userId);

        // 값이 존재한다면..(중복 회원 가입)
        if (rEntity.isPresent()) {
            res = 2;
        } else {

            // 회원가입을 위한 Entity 생성
            UserInfoEntity pEntity = UserInfoEntity.builder()
                    .userId(userId)
                    .userName(userName)
                    .password(password)
                    .email(email)
                    .addr1(addr1)
                    .addr2(addr2)
                    .roles(roles)
                    .regId(userId).regDt(DateUtil.getDateTime("yyyy-MM-dd hh:mm:ss"))
                    .chgId(userId).chgDt(DateUtil.getDateTime("yyyy-MM-dd hh:mm:ss"))
                    .build();

            // 회원정보 DB에 저장
            userInfoRepository.save(pEntity);

            /**
             * JPA 의 save 함수는 데이터 값에 따라 등록, 수정을 수행함
             * 물론 잘 저장되었겠지만, 내가 실행한 save 함수가 DB에 등록이 잘 수행되었는지 100% 확신이 불가능함
             * 회원가입 후, 혹시 저장이 안되었을수도 있기 때문에 조회를 수행함
             */
            rEntity = userInfoRepository.findByUserId(userId);

            if (rEntity.isPresent()) {  // 값이 존재한다면..(회원가입이 정상적으로 수행됨)
                res = 1;
            }
        }

        log.info(this.getClass().getName() + ".insertUserInfo End!");

        return res;
    }

    @Override
    public UserInfoDTO getUserInfo(UserInfoDTO pDTO) throws Exception {

        log.info(this.getClass().getName() + ".getUserInfo Start!");

        String user_id = CmmUtil.nvl(pDTO.userId());

        log.info("user_id : " + user_id);

        UserInfoDTO rDTO = null;

        // SELECT * FROM USER_INFO WHERE USER_ID = 'hglee67' 쿼리 실행과 동일
        Optional<UserInfoEntity> rEntity = userInfoRepository.findByUserId(user_id);

        if (rEntity.isPresent()) {

            /**
             * Entity -> DTO 로 변경
             * DB에 저장된 암호화된 Email 값을 복호화해서 DTO 에 저장하기 위해 ObjectMapper 사용 안함
             */
            rDTO = UserInfoDTO.builder()
                    .userId(CmmUtil.nvl(rEntity.get().getUserId()))
                    .userName(CmmUtil.nvl(rEntity.get().getUserName()))
                    .email(EncryptUtil.decAES128CBC(CmmUtil.nvl(rEntity.get().getEmail())))
                    .addr1(CmmUtil.nvl(rEntity.get().getAddr1()))
                    .addr2(CmmUtil.nvl(rEntity.get().getAddr2()))
                    .build();
        }

        log.info(this.getClass().getName() + ".getUserInfo End!");

        return rDTO;
    }
}
