from datetime import datetime, timedelta
from email import message
from http import HTTPStatus
import http
from flask import request
from flask_jwt_extended import create_access_token, get_jwt, get_jwt_identity, jwt_required
from flask_restful import Resource
from mysql.connector.errors import Error
from mysql_connection import get_connection
import mysql.connector
from email_validator import validate_email, EmailNotValidError

from utils import check_password, hash_password

#회원관리
# 경로 : /user
class User(Resource):
    # 회원가입저장
    # 메소드 : post
    # 데이터 : email, password, name
    def post(self):
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "name": "홍길동",
        #     "email": "abc@naver.com",
        #     "password": "1234"
        # }
        data=request.get_json()
        #print(data)

        name=data['name']
        email=data['email']
        password=data['password']

        #이메일 주소형식이 제대로 된 주소형식인지 확인하는 코드 작성.
        try:
            # Validate & take the normalized form of the email
            # address for all logic beyond this point (especially
            # before going to a database query where equality
            # does not take into account normalization).
            validated_email = validate_email(email).email
            #print(validated_email)
            #return {"validate_email":"success"}, HTTPStatus.OK
        except EmailNotValidError as e:
            # email is not valid, exception message is human-readable
            #print('error : ' + str(e))
            return {"error":str(e)}, HTTPStatus.BAD_REQUEST

        #비밀번호 정책을 확인한다. 자리수는 4자리이상 12자리 이하로 가능하게...
        if len(password)<4 or len(password)>12:
            return {"error":'비밀번호 길이(4~12)를 확인하세요.'}, HTTPStatus.BAD_REQUEST

        #비밀번호를 암호화 한다.
        hashed_password=hash_password(password)
        #print(hashed_password)
        #print(check_password(password, hashed_password))

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''insert into users
                    (name, email, password)
                    values
                    (%s,%s,%s)
                    ; '''

            record=(name, validated_email, hashed_password)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            # db에 저장된 아이디값 가져오기.
            # 자동증가된 id컬럼 값
            user_id=cursor.lastrowid

            #클라이언트에 user_id도 포함하여 응답해야 한다.
            #return {"result":"success", "user_id":user_id}, HTTPStatus.OK
            #user_id값은 보안이 중요하다, 해킹 가능성이 있으므로
            #JWT로 암호화해서 보낸다.
            access_token=create_access_token(user_id)

            return {"result":"success", "access_token":access_token}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            connection.rollback()
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

jwt_blacklist=set()     #로그아웃 한 토큰 집합(데이터)
#로그인아웃관리
# 경로 : /login-out
class LoginOut(Resource):
    #로그인
    # 메소드 : get
    # 데이터(get은 params를 사용한다.) : email, password
    def get(self):
        #1.요청 body에서 데이터를 가져온다.
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "email": "abc@naver.com",
        #     "password": "1234"
        # }
        # data=request.get_json()
        # #print(data)

        # email=data['email']
        # password=data['password']

        email=request.args['email']
        password=request.args['password']
        
        #2.이메일 검증
        #이메일 주소형식이 제대로 된 주소형식인지 확인하는 코드 작성.
        try:
            # Validate & take the normalized form of the email
            # address for all logic beyond this point (especially
            # before going to a database query where equality
            # does not take into account normalization).
            validated_email = validate_email(email).email
            #print(validated_email)
            #return {"validate_email":"success"}, HTTPStatus.OK
        except EmailNotValidError as e:
            # email is not valid, exception message is human-readable
            #print('error : ' + str(e))
            return {"error":"이메일 형식을 확인해 주세요"}, HTTPStatus.BAD_REQUEST

        #3.비밀번호 정책 확인
        #비밀번호 정책을 확인한다. 자리수는 4자리이상 12자리 이하로 가능하게...
        if len(password)<4 or len(password)>12:
            return {"error":'비밀번호 길이(4~12)를 확인하세요.'}, HTTPStatus.BAD_REQUEST

        #4.이메일로 사용자정보 조회
        try:
            # db접속
            connection = get_connection()

            query='''select *
                    from users
                    where email=%s
                    ;'''

            record=(validated_email,)

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            if len(result_list) != 1:
                return {"error":"회원정보가 없습니다. 회원가입을 먼저 하세요"}, HTTPStatus.BAD_REQUEST

            #5.비밀번호 비교
            check=check_password(password, result_list[0]['password'])
            if check==False:
                return {"error":"비밀번호가 틀립니다. 확인하세요."}, HTTPStatus.BAD_REQUEST

            #중요! db에서 가져온 timestamp데이터타입은 파이썬의 datetime으로 자동 변경된다.
            #이 데이터는 json으로 바로 보낼 수 없으므로 문자열로 바꿔서 다시 저장해서 보낸다.
            i=0
            for record in result_list:
                result_list[i]['created_at'] = record['created_at'].isoformat()
                result_list[i]['updated_at'] = record['updated_at'].isoformat()
                i=i+1

            #6.응답
            # return {"result":"success",
            #         "count":len(result_list),
            #         "result_list":result_list}, HTTPStatus.OK
            
            user_id=result_list[0]['user_id']
            username=result_list[0]['name']
            #user_id값은 보안이 중요하다, 해킹 가능성이 있으므로
            #JWT로 암호화해서 보낸다.
            access_token=create_access_token(user_id)
            #토큰 유효기한 셋팅
            #access_token=create_access_token(user_id, expires_delta=timedelta(minutes=1))
            
            return {"result":"success", "access_token":access_token, "name":username}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()

    #로그아웃
    # 메소드 : post
    # 데이터 : header:user_id토큰
    @jwt_required(optional=False)
    def post(self):
        jti=get_jwt()['jti']        #토큰을 가져온다.
        #print(jti)
        jwt_blacklist.add(jti)      #토큰을 집합에 넣는다.
        return {"result":"success"}, HTTPStatus.OK

#메모관리
# 경로 : /memo
class Memo(Resource):
    #생성
    # 메소드 : post
    # 데이터 : header:user_id토큰, body=제목, 일시분, 내용
    @jwt_required()
    def post(self):
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "title": "메모1",
        #     "todo_date": "시간은 어찌",
        #     "contents": "할일은 하자.."
        # }
        data=request.get_json()
        #print(data)

        title=data['title']
        todo_date=data['todo_date']
        contents=data['contents']

        #str_datetime='2021-07-18 12:15:33'
        format='%Y-%m-%d %H:%M:%S'
        todo_date=datetime.strptime(todo_date,format)

        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''insert into memo
                    (user_id, title, todo_date, contents)
                    values
                    (%s,%s,%s,%s)
                    ; '''

            record=(user_id, title, todo_date, contents)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            # db에 저장된 아이디값 가져오기.
            # 자동증가된 id컬럼 값
            memo_id=cursor.lastrowid

            #클라이언트에 memo_id도 포함하여 응답해야 한다.
            return {"result":"success", "memo_id":memo_id}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            connection.rollback()
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

    #조회
    # 메소드 : get
    # 데이터 : header:user_id토큰, body=offset,limit,제목검색어
    # 데이터(get은 params를 사용한다.) : header:user_id토큰, params=?offset=0&limit=25&제목검색어
    @jwt_required()
    def get(self):
        #1.요청 body에서 데이터를 가져온다.
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "sch_title": "1",
        #     "offset": "0",
        #     "limit": "3",
        # }
        # data=request.get_json()
        # #print(data)

        # sch_title=data['sch_title']
        # offset=data['offset']
        # limit=data['limit']

        #1.요청 params에서 데이터를 가져온다.
        #request.args는 딕셔너리다.
        #offset=request.args['offset']
        #offset=request.args.get('offset')
        sch_title=request.args['sch_title']
        offset=request.args['offset']
        limit=request.args['limit']
        
        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        #4.메모 조회
        try:
            # db접속
            connection = get_connection()

            query='''select memo_id, title, todo_date, contents, created_at, updated_at
                    from memo
                    where user_id=%s
                      and title like '%'''+sch_title+'''%' 
                    order by todo_date desc 
                    limit '''+offset+''','''+limit+''';'''

            #record=(user_id, offset, limit)
            record=(user_id,)

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            #중요! db에서 가져온 timestamp데이터타입은 파이썬의 datetime으로 자동 변경된다.
            #이 데이터는 json으로 바로 보낼 수 없으므로 문자열로 바꿔서 다시 저장해서 보낸다.
            i=0
            for record in result_list:
                result_list[i]['todo_date'] = record['todo_date'].isoformat()
                result_list[i]['created_at'] = record['created_at'].isoformat()
                result_list[i]['updated_at'] = record['updated_at'].isoformat()
                i=i+1

            return {"result":"success",
                    "count":len(result_list),
                    "result_list":result_list}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()

#메모관리
# 경로 : /memo/<int:memo_id>
class MemoModify(Resource):
    #수정
    # 메소드 : put
    # 데이터 : header:user_id토큰, body=제목, 일시분, 내용
    @jwt_required()
    def put(self, memo_id):
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "title": "메모1",
        #     "todo_date": "시간은 어찌",
        #     "contents": "할일은 하자.."
        # }
        data=request.get_json()
        #print(data)

        title=data['title']
        todo_date=data['todo_date']
        contents=data['contents']

        #str_datetime='2021-07-18 12:15:33'
        format='%Y-%m-%d %H:%M:%S'
        todo_date=datetime.strptime(todo_date,format)

        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''update memo
                    set title=%s
                        ,todo_date=%s
                        ,contents=%s
                    where memo_id=%s
                      and user_id=%s
                    ;'''

            record=(title, todo_date, contents, memo_id, user_id)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            if cursor.rowcount >= 1:
                return {"result":"success"}, HTTPStatus.OK
            else:
                return {"result":"failed", "message":"메모가 존재하지 않거나 본인의 메모인지 확인바랍니다."}, HTTPStatus.BAD_REQUEST

        except mysql.connector.Error as e:
            print(e)
            connection.rollback()
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

    #삭제
    # 메소드 : delete
    # 데이터 : header:user_id토큰
    @jwt_required()
    def delete(self, memo_id):
        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''delete from memo
                    where memo_id=%s
                      and user_id=%s
                    ;'''

            record=(memo_id, user_id)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            if cursor.rowcount >= 1:
                return {"result":"success"}, HTTPStatus.OK
            else:
                return {"result":"failed", "message":"메모가 존재하지 않거나 본인의 메모인지 확인바랍니다."}, HTTPStatus.BAD_REQUEST

        except mysql.connector.Error as e:
            print(e)
            connection.rollback()
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

#친구관리
# 경로 : /follow
class Follow(Resource):
    #친구메모조회
    # 메소드 : get
    # 데이터 : header:user_id토큰, body=offset,limit,followee회원명검색어, 제목검색어
    # 데이터(get은 params를 사용한다.) : header:user_id토큰, params=?offset=0&limit=25&제목검색어&회원명검색어&일자
    @jwt_required()
    def get(self):
        #1.요청 body에서 데이터를 가져온다.
        #클라이언트에서 보낸 body의 json데이터를 받아오는 코드
        # {
        #     "sch_followee_name": "1",
        #     "sch_title": "1",
        #     "sch_todo_date": "2022-06-19",
        #     "offset": "0",
        #     "limit": "3",
        # }
        # data=request.get_json()
        # #print(data)

        # sch_followee_name=data['sch_followee_name']
        # sch_title=data['sch_title']
        # offset=data['offset']
        # limit=data['limit']
        # sch_todo_date=data['sch_todo_date']

        sch_followee_name=request.args['sch_followee_name']
        sch_title=request.args['sch_title']
        sch_todo_date=request.args['sch_todo_date']
        offset=request.args['offset']
        limit=request.args['limit']

        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        #친구메모 조회
        try:
            # db접속
            connection = get_connection()

            query='''select a.followee_id, b.name, c.title, c.todo_date, c.contents
                    from follow a join users b
                        on a.followee_id=b.user_id join memo c
                        on b.user_id=c.user_id
                    where a.follow_id=%s
                      and date(c.todo_date) like concat(%s, '%')
                      and b.name like concat('%', %s, '%')
                      and c.title like concat('%', %s, '%')
                    order by a.followee_id, c.todo_date desc 
                    limit %s, %s
                    ;'''
                    
            record=(user_id, sch_todo_date, sch_followee_name, sch_title, int(offset), int(limit))
            #record=(user_id, )

            # 커서(딕셔너리 셋으로 가져와라)
            #select문은 dictionary=True 한다.
            cursor=connection.cursor(dictionary=True)

            # 실행
            cursor.execute(query, record)
            
            # 데이터fetch : select문은 아래함수를 이용해서 데이터를 가져온다.
            result_list=cursor.fetchall()
            #print(result_list)

            #중요! db에서 가져온 timestamp데이터타입은 파이썬의 datetime으로 자동 변경된다.
            #이 데이터는 json으로 바로 보낼 수 없으므로 문자열로 바꿔서 다시 저장해서 보낸다.
            i=0
            for record in result_list:
                result_list[i]['todo_date'] = record['todo_date'].isoformat()
                i=i+1

            return {"result":"success",
                    "count":len(result_list),
                    "result_list":result_list}, HTTPStatus.OK

        except mysql.connector.Error as e:
            print(e)
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE

        finally:
            # 자원해제
            #print('finally')
            cursor.close()
            connection.close()

#친구관리
# 경로 : /follow/<int:followee_id>
class FollowModify(Resource):
    #친구맺기
    # 메소드 : post
    # 데이터 : header:user_id토큰
    @jwt_required()
    def post(self, followee_id):
        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        # print(type(followee_id))
        # print(type(user_id))

        if str(followee_id)==str(user_id):
            print('return')
            return {"error":"자신을 친구맺기 할 수 없습니다."}, HTTPStatus.BAD_REQUEST

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''insert into follow
                    (follow_id, followee_id)
                    values
                    (%s,%s)
                    ; '''

            record=(user_id, followee_id)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            return {"result":"success"}, HTTPStatus.OK

        except mysql.connector.Error as e:
            connection.rollback()

            print("Error code:", e.errno)        # error number
            print("SQLSTATE value:", e.sqlstate) # SQLSTATE value
            print("Error message:", e.msg)       # error message
            print(e)

            if e.errno==1062:
                return {"error":"이미 followee입니다."}, HTTPStatus.BAD_REQUEST
            elif e.errno==1452:
                return {"error":"해당 followee가 존재하지 않습니다."}, HTTPStatus.BAD_REQUEST
            else:
                return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()

    #친구끊기
    # 메소드 : delete
    # 데이터 : header:user_id토큰
    @jwt_required()
    def delete(self, followee_id):
        #user_id를 create_access_token(user_id)로 암호화 했다.
        #인증토큰을 복호화 한다.
        user_id=get_jwt_identity()

        try:
            # 데이터 인서트
            # db접속
            connection = get_connection()

            # 쿼리작성
            query='''delete from follow
                    where follow_id=%s
                      and followee_id=%s
                    ;'''

            record=(user_id, followee_id)

            # 커서
            cursor=connection.cursor()

            # 실행
            cursor.execute(query, record)

            # 커밋
            connection.commit()

            if cursor.rowcount >= 1:
                return {"result":"success"}, HTTPStatus.OK
            else:
                return {"result":"failed", "message":"친구가 존재하지 않거나 본인의 친구인지 확인바랍니다."}, HTTPStatus.BAD_REQUEST

        except mysql.connector.Error as e:
            print(e)
            connection.rollback()
            return {"error":str(e)}, HTTPStatus.SERVICE_UNAVAILABLE
        
        finally:
            cursor.close()
            connection.close()



