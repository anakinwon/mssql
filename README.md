MS-SQL 인프라 취약점 점검

```
DECLARE @name VARCHAR(50)
DECLARE @type VARCHAR(50)
DECLARE @pass VARCHAR(100)
DECLARE @cnt int
DECLARE @cnt_1 int
DECLARE @dis int
DECLARE @date VARCHAR(50)
DECLARE @check sql_variant
DECLARE @class VARCHAR(100)
DECLARE @database VARCHAR(50)
DECLARE @permission VARCHAR(50)
DECLARE @protocol VARCHAR(50)
DECLARE @result_1 int
DECLARE @result table(name varchar(100))
DECLARE @result2 table(value varchar(500))

print '======================================================================================= '
print '###############        EGISIT DBMS(MS-SQL) Security Check         ###############'
print '############### Copyright 2017 EGISIT Co. Ltd. All right Reserved ###############'
print '======================================================================================= '

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-1] 기본계정의 패스워드, 정책 등을 변경하여 사용'
PRINT '      ① SA 계정 패스워드 설정 유무 점검'
PRINT '      ② 취약한 패스워드 사용여부 점검'
PRINT '======================================================================='
PRINT '① SA 계정 패스워드 설정 유무 점검'
PRINT ''
Select name, password from sys.syslogins where name='sa'

select @pass = ISNULL(password,0) from sys.syslogins where name='sa' group by password
IF @pass='0'
	BEGIN
			PRINT '취약'
			insert into @result(name) values('D-1-① : 취약')
	END
ELSE
	PRINT '양호'
	insert into @result(name) values('D-1-① : 양호')

PRINT ' '
PRINT '[CHECK] 출력된 계정의 password에 NULL값이 존재하면 취약'
PRINT ''
PRINT '② 취약한 패스워드 사용여부 점검'
PRINT ''
SELECT @cnt = count(NAME) FROM SYS.SYSLOGINS WHERE PWDCOMPARE(NAME,PASSWORD) = 1 
IF @cnt = 0
	BEGIN
		PRINT '계정명과 동일한 패스워드를 사용하는 계정이 존재하지 않음'
		PRINT ''
		PRINT '양호'
		insert into @result(name) values('D-1-② : 양호')
	END
ELSE
    BEGIN
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @name= NAME FROM SYS.SYSLOGINS WHERE PWDCOMPARE(NAME,PASSWORD) = 1 
			PRINT 'Name : ' + @name
			SET @cnt = @cnt - 1
			
		END
		PRINT ''
		PRINT '취약'
		insert into @result(name) values('D-1-② : 취약')
    END
    
PRINT ' '
PRINT '[CHECK] 양호로 출력되면 양호이며, 계정명이 출력되면 계정명과 동일한 취약한 패스워드를 사용하는 계정이 출력된 것으로 취약'

PRINT ' '
PRINT '[D-1] END'

PRINT '======================================================================='
PRINT '두 진단 항목 모두 양호로 확인되어야 양호로 판단'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-2] scott 등 Demonstration 및 불필요 계정을 제거하거나 잠금설정 후 사용'
PRINT '      MS-SQL 진단기준에 적용하여 아래항목을 점검'
PRINT '      ① 불필요한 계정 존재여부 점검'
PRINT '      ② SA계정 Disable 유무 점검'
PRINT '      ③ Guest계정 Disable 유무 점검'
PRINT '======================================================================='
PRINT '① 불필요한 계정 존재여부 점검'
PRINT ''
SELECT @cnt = count(NAME) FROM SYS.SYSLOGINS
IF @cnt = 0
	BEGIN		
		PRINT 'No results'
	END
		
ELSE
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @name= NAME FROM SYS.SYSLOGINS ORDER BY NAME
			PRINT '계정명 : '+@name
			SET @cnt = @cnt - 1			
		END		
PRINT ''
PRINT '[CHECK] DBMS에 존재하는 모든계정 출력 결과를 확인 후 인터뷰'

insert into @result2(value) values('D-2-① 기준 : 계정을 목록화 하여 관리 되지 않고, 불필요 계정이 존재 하면 취약')
insert into @result(name) values('D-2-① : 결과 확인 후 인터뷰')

PRINT ''
PRINT '② SA계정 Disable 유무 점검'
PRINT ''
SELECT @dis = IS_DISABLED FROM SYS.SQL_LOGINS WHERE NAME='SA'
IF @dis = 1
	BEGIN
		PRINT 'Disable'
		PRINT ''
		PRINT '양호'
		insert into @result(name) values('D-2-② : 양호')
	END
ELSE
	BEGIN
		PRINT 'Enable'
		PRINT ''
		PRINT '취약'
		insert into @result(name) values('D-2-② : 취약')
	END
PRINT ''
PRINT '[CHECK] Disable 출력시 양호, Enable출력 시 취약'

PRINT ''
PRINT '③ Guest계정 Disable 유무 점검'
PRINT ''
EXEC sp_MSForEachDB '
DECLARE @cnt int
SELECT @cnt=COUNT(*) FROM ?.SYS.DATABASE_PERMISSIONS WHERE PERMISSION_NAME=''CONNECT'' AND GRANTEE_PRINCIPAL_ID=2
IF @cnt = 0 
 BEGIN
  PRINT ''? - Disable'' 
  
 END
ELSE
  PRINT ''? - Enable''
'
PRINT ''
PRINT '[CHECK] 전체 Database에 존재하는 Guest계정 Enable/Disable 여부 확인 후 판단'

insert into @result(name) values('D-2-③ : 결과 확인')

PRINT ' '
PRINT '[D-2] END'

PRINT '======================================================================='
PRINT '세 진단 항목 모두 양호로 확인되어야 양호로 판단'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-3] 패스워드의 사용기간 및 복잡도를 기관의 정책에 맞도록 설정'
PRINT '      MS-SQL 진단기준에 적용하여 아래항목을 점검'
PRINT '      ① 암호 만료 강제 적용 설정 점검'
PRINT '      ② 암호 정책 강제 적용 설정 점검'
PRINT '======================================================================='
PRINT '① 암호 만료 강제 적용 설정 점검'
PRINT ''
SELECT @cnt = count(NAME) FROM SYS.SQL_LOGINS WHERE IS_EXPIRATION_CHECKED=0
IF @cnt = 0
	BEGIN
		PRINT '패스워드 변경주기를 적절하게 설정하고 있음'
		PRINT ' '
		PRINT '양호'
		insert into @result(name) values('D-3-① : 양호')
	END
ELSE
    BEGIN
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @name= NAME FROM SYS.SQL_LOGINS WHERE IS_EXPIRATION_CHECKED=0 
			PRINT '계정명 : ' + @name
			SET @cnt = @cnt - 1
		END
		PRINT ' '
		PRINT '취약'
		insert into @result(name) values('D-3-① : 취약')
    END
PRINT ' '
PRINT '[CHECK] 암호 만료 강제 적용 설정이 미흡한 계정이 진단결과에 출력되면 취약'
PRINT '        ※ Windows인증 방식을 통해 DBMS 운영 시 점검 방법'
PRINT '          * 시작 -> 실행 -> secpol.msc -> 보안 설정 -> 계정 정책 -> 암호 정책 메뉴를 통해 정책 설정 상태 점검 (최대 암호 사용 기간 Check - 안행부 권고 90일) '
PRINT '        서버진단 참고항목[W-11]패스워드 최대 사용기간 항목참고'
PRINT ''
PRINT '② 암호 정책 강제 적용 설정 점검'
PRINT ''
SELECT @cnt = count(NAME) FROM SYS.SQL_LOGINS WHERE IS_POLICY_CHECKED=0
IF @cnt = 0
	BEGIN
		PRINT '암호 정책을 강제 적용하고 있음'
		PRINT ' '
		PRINT '양호'
		insert into @result(name) values('D-3-② : 양호')
	END
ELSE
    BEGIN
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @name= NAME FROM SYS.SQL_LOGINS WHERE IS_POLICY_CHECKED=0
			PRINT 'Name : ' + @name
			SET @cnt = @cnt - 1
		END
		PRINT ' '
		PRINT '취약'
		insert into @result(name) values('D-3-② : 취약')
    END

PRINT ''
PRINT '[CHECK] 암호 정책 강제 적용 설정이 미흡한 계정이 진단결과에 출력되면 취약'
PRINT '        ※ Windows인증 방식을 통해 DBMS 운영 시 점검 방법'
PRINT '          * 시작 -> 실행 -> secpol.msc -> 보안 설정 -> 계정 정책 -> 암호 정책 메뉴를 통해 정책 설정 상태 점검 (암호는 복잡성을 만족해야 함 Check - 사용여부) '
PRINT '         서버진단 참고항목[W-9] 패스워드 복잡성 설정항목참고'
PRINT ' '
PRINT '[D-3] END'

PRINT '======================================================================='
PRINT '※ 서버 취약점 점검을 수행하였을 경우 Windows 서버 진단결과 참조 (W-9, W-11)'
PRINT '두 진단 항목 모두 양호로 확인되어야 양호로 판단'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-4] 데이터베이스 관리자 권한을 꼭 필요한계정 및 그룹에 허용'
PRINT '======================================================================='

PRINT ' '
PRINT '- 관리자 권한을 갖고있는 계정 목록 - '
PRINT ' '
SELECT @cnt = count(NAME) FROM SYS.server_principals A, sys.server_role_members B WHERE A.principal_id = B.MEMBER_principal_id AND role_principal_id =3
IF @cnt = 0
	BEGIN
		PRINT 'NOT Result'
		insert into @result(name) values('D-4 :	양호')
		
	END
ELSE
	BEGIN
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @name= NAME 
			FROM SYS.server_principals A, sys.server_role_members B 
			WHERE A.principal_id = B.MEMBER_principal_id AND role_principal_id =3
			ORDER BY name
			PRINT '계정명 : ' + @name
			SET @cnt = @cnt - 1
			
		END
	END
PRINT ''
insert into @result(name) values('D-4 :	결과 확인 후 인터뷰')
PRINT ''
PRINT '[CHECK] 관리자가 아닌 사용자에게 DBA권한이 부여되어 있을경우 취약, 결과확인 후 인터뷰 필요'

PRINT ' '
PRINT '[D-4] END'
PRINT '======================================================================='
PRINT 'SA, SYSTEM, Windows 인증을 통한 SQL Server 로그인 계정은 예외'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-5] 패스워드 재사용 제약 설정'
PRINT '======================================================================='
PRINT ' '
PRINT '콘솔 확인 '
insert into @result(name) values('D-5 :	콘솔 확인')
PRINT ''
PRINT '[CHECK] Windows 인증을 통한 로그인 방식을 사용해야 진단가능/미사용 시 해당사항 없음'
PRINT '        ※ Windows인증 방식을 통해 DBMS 운영 시 점검 방법'
PRINT '          * 시작 -> 실행 -> secpol.msc -> 보안 설정 -> 계정 정책 -> 암호 정책 메뉴를 통해 정책 설정 상태 점검 (최근 암호 기억 Check - 5개 이상) '
PRINT '         서버진단 참고항목[W-16] 최근 암호 기억항목 참고'

PRINT ' '
PRINT '[D-5] END'
PRINT '======================================================================='
PRINT '※ 서버 취약점 점검을 수행하였을 경우 Windows 서버 진단결과 참조 (W-16)'
PRINT '최근 암호 기억 설정을 통해 이전에 사용하던 패스워드는 새로운 패스워드로 적용이 불가능하게 설정'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-6] DB 사용자 계정을 개별적으로 부여'
PRINT '======================================================================='
PRINT ' '
PRINT '1. 사용자 별 서버 권한 체크'
PRINT ' 계정 : Class : Database : Permission : Protocol'
PRINT ''

-- 계정 별 서버 권한 체크
SELECT @cnt = count(*) FROM sys.server_permissions a
	left join sys.server_principals b on a.grantee_principal_id = b.principal_id
	left join sys.endpoints c on a.major_id = c.endpoint_id

IF @cnt = 0
		PRINT 'No Results'
ELSE
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @class=class_desc, @database =default_database_name, @name = b.name, @permission = permission_name, @protocol = c.protocol_desc  from sys.server_permissions a
				left join sys.server_principals b on a.grantee_principal_id = b.principal_id
				left join sys.endpoints c on a.major_id = c.endpoint_id
			ORDER BY b.name
			PRINT isnull(@name,'Null') + ' : ' + isnull(@class,'Null') + ' : ' + isnull(@database,'Null') + ' : ' + isnull(@permission,'Null') + ' : ' + isnull(@protocol ,'Null')
			SET @cnt = @cnt - 1
		END
PRINT ''

PRINT '2. Database 별 사용자 Role 권한 체크'
PRINT '계정 : 권한(Role)'
PRINT ''
-- ROLE 체크
EXEC sp_MSForEachDB '
use ?
PRINT ''< ? >''
DECLARE @cnt int
DECLARE @name VARCHAR(50)
DECLARE @type VARCHAR(50)
SELECT @cnt=COUNT(*) 
FROM sys.database_principals u
	JOIN (sys.database_role_members m join sys.database_principals r on m.role_principal_id = r.principal_id) on u.principal_id = m.member_principal_id
	JOIN sys.server_principals l on u.sid = l.sid
WHERE u.type<>''R'' and r.name <> ''null''
IF @cnt = 0
	PRINT ''No Results''
ELSE
	WHILE 0 != @cnt
		BEGIN
		SELECT TOP (@cnt) @name = l.name, @type = r.name
		FROM sys.database_principals u
		JOIN (sys.database_role_members m join sys.database_principals r on m.role_principal_id = r.principal_id) on u.principal_id = m.member_principal_id
		JOIN sys.server_principals l on u.sid = l.sid
		WHERE u.type<>''R'' and r.name <> ''null''
		PRINT @name+'':''+@type
		SET @cnt = @cnt - 1
		END
	PRINT ''''
'
PRINT ''
insert into @result(name) values('D-6 :	결과 확인 후 인터뷰')

PRINT ''
PRINT '[CHECK] 계정별로 데이터베이스에 대한 역할멤버(Database role)를 확인하여 필요이상의 권한이 주어져 있는지 확인'

PRINT ' '
PRINT '[D-6] END'
PRINT '======================================================================='
PRINT '1, 2의 출력결과를 참조하여 담당자와 인터뷰를 통해 판단해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-7] 원격에서 DB서버로의 접속 제한'
PRINT '======================================================================='
PRINT ' '
PRINT '콘솔 확인 '
insert into @result(name) values('D-7 :	콘솔 확인')
PRINT ''
PRINT '[CHECK] 시작 -> 모든 프로그램 -> Microsoft SQL Server 2005 or 2008 -> 구성 도구 -> SQL Server 구성 관리자 '
PRINT '        -> SQL Server 네트워크 구성 -> TCP/IP -> IP 주소 -> TCP 포트 확인 (Default Port 1433 여부)'
PRINT ''
PRINT '          ※ Default TCP 1433 Port를 사용중이면 취약하나 OS 자체 방화벽 또는 방화벽, DB접근제어 시스템등과 같은 보안장비를 통해 허용할 IP에 대해서만 접근제어 설정을 하고있을 경우 양호'
PRINT '          Windows 스크립트결과물 73라인 Active Connections LISTEN 포트리스트 확인'

PRINT ' '
PRINT '[D-7] END'
PRINT '======================================================================='
PRINT '콘솔을 통해 접근제어 설정 확인과 담당자와 인터뷰를 통해 판단해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-8] DBA 이외의 인가되지 않은 사용자 시스템 테이블 접근 제한 설정'
PRINT '======================================================================='
PRINT ' '
PRINT '- Object의 사용권한에 Public Role이 부여된 시스템 테이블 출력 -'
PRINT ''
select U.name as [PRINCIPAL], T.name as [TABLE], P.permission_name as [PERMISSION],
P.state_desc as [STATE]
from sys.database_principals U
join sys.database_permissions P on U.principal_id=P.grantee_principal_id
join sys.tables T on P.major_id=T.object_id
where P.state_desc<>'DENY' and T.is_ms_shipped=1 order by U.name, T.name
PRINT ''
PRINT '[CHECK] 출력된 테이블들은 Public Role 부여로 미흡한 상태이지만 사이트 구성 환경의 특성에 따라 '
PRINT '        Public Role을 사용할 수 있기 때문에 담당자와 인터뷰 후 양호, 취약 여부를 판단해야 함'
PRINT ''
PRINT '          ※ 취약하다고 판단되어 조치 권고 시 문제가 발생할 수 있기 때문'

PRINT ''
insert into @result(name) values('D-8 :	결과 확인 후 인터뷰')
       
PRINT ' '
PRINT '[D-8] END'
PRINT '======================================================================='
PRINT '출력 결과를 참조하여 담당자와 인터뷰를 통해 판단해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-9] 오라클 데이터베이스의 경우 리스너 패스워드 설정'
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL은 해당사항 없음 '
PRINT ''
insert into @result(name) values('D-9 : N/A')
PRINT ' '
PRINT '[D-9] END'
PRINT '======================================================================='
PRINT '콘솔을 통해 설정사항을 확인해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-10] 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거'
PRINT '======================================================================='
PRINT ''
PRINT '콘솔 확인 '
PRINT ' '
PRINT '[CHECK] 시작 -> 설정 -> 제어판 -> 관리도구 -> 데이터 원본 (ODBC) -> 시스템DSN -> 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 확인 '
PRINT ''
PRINT '          ※ 서버 취약점 점검을 수행하였을 경우 [W-52] 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거항목 참고'
PRINT ' '
insert into @result(name) values('D-10 : 콘솔 확인')
PRINT ' '
PRINT '[D-10] END'
PRINT '======================================================================='
PRINT '콘솔을 통해 설정사항을 확인해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-11] 일정 횟수의 로그인 실패시 이에 대한 잠금정책 설정 '
PRINT '======================================================================='
PRINT ''
PRINT '콘솔 확인 '
PRINT ' '
PRINT '[CHECK] 시작 -> 실행 -> secpol.msc -> 보안 설정 -> 계정 정책 -> 계정 잠금 정책 -> 계정 잠금 임계값 확인 (3회 이상) '
PRINT ''
PRINT '          ※ 서버 취약점 점검을 수행하였을 경우 Windows 서버 진단결과 참조 (W-04, W-08)'
PRINT '          ※ 계정 잠금 임계값이 3회 이상, 계정 잠금 기간이 60분 이상으로 설정되어 있을 시 양호, 미 설정 시 취약, Windows 인증 방식을 사용하고 있지 않은 경우도 취약'
PRINT ' '
insert into @result(name) values('D-11 : N/A')
PRINT ' '
PRINT '[D-11] END'
PRINT '======================================================================='
PRINT '콘솔을 통해 설정사항을 확인해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-12] 데이터베이스의 주요 파일 보호 등을 위해 DB 계정의 umask를 022 이상으로 설정 '
PRINT '       MS-SQL 진단기준에 적용하여 아래항목을 점검'
PRINT '       SQL Server 데이터 디렉터리의 엑세스 제어 목록(ACL)이 적절하게 설정되어 있는지 점검'
PRINT '======================================================================='
PRINT ''
PRINT '콘솔 확인 '
PRINT ' '
PRINT '1. 데이터베이스의 파일 디렉터리 경로를 확인 '
PRINT ''
select DB_NAME(database_id) as 'Database', name, physical_name from sys.master_files
PRINT ''
PRINT '2. 위 출력결과에서 확인된 경로의 ACL이 적절하게 설정되어 있는지 확인 '
PRINT ''
PRINT '확인된 경로의 ex> - Program Files\Microsoft SQL Server\MSSQL$InstanceName\Binn'
PRINT '                - Program Files\Microsoft SQL Server\MSSQL$InstanceName\Data'
PRINT '                - Program Files\Microsoft SQL Server\MSSQL$InstanceName\LOG'
PRINT '                - Program Files\Microsoft SQL Server\MSSQL$InstanceName\Backup 등의 경로에 대해'
PRINT 'SQL Server service accounts 와 local Administrators 계정만 접근 가능하도록 설정되어 있는지 확인'
PRINT ''
PRINT '[CHECK] Everyone:(F)의 권한 제거하고 꼭 필요한 권한만 부여하였는지 확인 '
PRINT ' '
insert into @result(name) values('D-12 : 콘솔 확인 N/A')
PRINT ' '
PRINT '[D-12] END'
PRINT '======================================================================='
PRINT '콘솔을 통해 설정사항을 확인해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-13] 데이터베이스의 주요 설정파일, 패스워드 파일 등과 같은 주요 파일들의 접근권한 설정 '
PRINT '======================================================================='
PRINT ''
PRINT '콘솔 확인 '
PRINT ' '
PRINT '[CHECK] D-12의 진단결과로 양호, 취약여부 판단 가능 '
PRINT ''
insert into @result(name) values('D-13 : 콘솔 확인')
PRINT ''
PRINT '[D-13] END'
PRINT '======================================================================='
PRINT 'D-12의 진단결과 확인 후 판단'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-14] 관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 설정 '
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL은 해당사항 없음 '
PRINT ''
insert into @result(name) values('D-14 : N/A')
PRINT ''
PRINT '[D-14] END'
PRINT '======================================================================='
PRINT 'MS-SQL은 해당사항 없음'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-15] 응용 프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정 '
PRINT '======================================================================='
PRINT ''
PRINT '콘솔 확인 '
PRINT ' '
PRINT '[CHECK] 시작 -> 모든 프로그램 -> Microsoft SQL Server 2005 or 2008 -> SQL Server Management Studio '
PRINT '        -> 개체 탐색기에서 서버 선택 -> 하위메뉴의 보안 선택 -> 하위메뉴의 로그인 선택 (서버역할 에서 Role로서 권한부여 여부 확인 가능) '
PRINT '        -> 계정별 속성 메뉴 -> 보안 개체 페이지 -> 검색 버튼 -> 서버 ''인스턴스 네임'' -> Role로서 권한을 부여하고 있는지 여부 확인 '
PRINT ''
PRINT '          ※ 명시적으로 권한을 부여하는 경우 취약, 단 명시적 권한 부여설정 중 ''SQL 연결'' 권한은 예외'
PRINT ' '
SELECT user_name(p.grantee_principal_id) 'User', o.name 'Object',p.permission_name 
FROM sys.objects o, sys.database_permissions p
WHERE o.object_id=p.major_id AND p.grantee_principal_id in(0,2)
insert into @result(name) values('D-15 : 콘솔 확인')
PRINT ' '
PRINT '[D-15] END'
PRINT '======================================================================='
PRINT '콘솔을 통해 설정사항을 확인해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-16] OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정 '
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL은 해당사항 없음 '
PRINT ''
insert into @result(name) values('D-16 : N/A')
PRINT ' '
PRINT '[D-16] END'

PRINT '======================================================================='
PRINT '네 진단 항목 모두 양호로 확인되어야 양호로 판단'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-17] 패스워드 확인함수 설정 '
PRINT '======================================================================='
PRINT ''
PRINT '콘솔 확인 '
PRINT ' '
PRINT '[CHECK] Windows 인증방식을 사용 시 Windows의 계정 정책을 적용받기 때문에 D-03 진단결과 패스워드 복잡성 설정이 되어 있다면 양호로 판단함 '
PRINT ''
SELECT name, is_disabled FROM sys.sql_logins WHERE type='S' AND is_policy_checked <> '1' 
insert into @result(name) values('D-17 : 콘솔 확인 N/A')
PRINT ' '
PRINT '[D-17] END'
PRINT '======================================================================='
PRINT 'D-03의 진단결과 확인 후 판단'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-18] 인가되지 않은 Object Owner의 존재 여부 '
PRINT '======================================================================='
PRINT ''
SELECT @cnt = COUNT(DISTINCT O.type_desc) 
FROM SYS.DATABASE_PRINCIPALS U 
	JOIN SYS.DATABASE_PERMISSIONS P ON U.PRINCIPAL_ID=P.GRANTEE_PRINCIPAL_ID 
	JOIN SYS.ALL_OBJECTS O ON P.MAJOR_ID=O.OBJECT_ID 
WHERE P.STATE_DESC <> 'DENY' AND U.NAME IN ('GUEST','PUBLIC')
IF @cnt = 0
	BEGIN
		PRINT 'No Results'
		PRINT ''
		PRINT '양호'
		insert into @result(name) values('D-18 : 양호')
	END
ELSE
    BEGIN
	WHILE @cnt != 0
		BEGIN
			SELECT DISTINCT TOP (@cnt) @type = O.type_desc
			FROM SYS.DATABASE_PRINCIPALS U 
				JOIN SYS.DATABASE_PERMISSIONS P ON U.PRINCIPAL_ID=P.GRANTEE_PRINCIPAL_ID 
				JOIN SYS.ALL_OBJECTS O ON P.MAJOR_ID=O.OBJECT_ID 
			WHERE P.STATE_DESC <> 'DENY' AND U.NAME IN ('GUEST','PUBLIC')

			SELECT @cnt_1 = COUNT(DISTINCT O.name) 
			FROM SYS.DATABASE_PRINCIPALS U 
				JOIN SYS.DATABASE_PERMISSIONS P ON U.PRINCIPAL_ID=P.GRANTEE_PRINCIPAL_ID 
				JOIN SYS.ALL_OBJECTS O ON P.MAJOR_ID=O.OBJECT_ID 
			WHERE P.STATE_DESC <> 'DENY' AND U.NAME IN ('GUEST','PUBLIC') AND O.type_desc = @type
			PRINT @TYPE + ' : '+ STR(@cnt_1)+ '개'
			SET	@cnt = @cnt - 1
		END
		PRINT ''
		PRINT '결과 확인 후 인터뷰'
		insert into @result(name) values('D-18 : 결과 확인 후 인터뷰')
    END
PRINT ' '
PRINT '[CHECK] No Results가 출력되면 양호, '
PRINT '        출력된 테이블들은 Public Role 부여로 미흡한 상태이지만 사이트 구성 환경의 특성에 따라 '
PRINT '        Public Role을 사용할 수 있기 때문에 담당자와 인터뷰 후 양호, 취약 여부를 판단해야 함'
PRINT ''
PRINT '          ※ 취약하다고 판단되어 조치 권고 시 문제가 발생할 수 있기 때문'

PRINT ''
PRINT '[D-18] END'

PRINT '======================================================================='
PRINT 'GUEST와 PUBLIC 권한으로 접근 가능한 Object Group과 Object 개수가 출력되면 담당자와 인터뷰를 통해 취약 여부를 판단해야 함'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-19] grant option이 role에 의해 부여되도록 설정 '
PRINT '======================================================================='
PRINT ' '
EXEC sp_MSForEachDB '
use ?
PRINT ''< ? >''
DECLARE @name VARCHAR(50)
DECLARE @cnt int

SELECT @cnt = COUNT(*) 
FROM SYS.DATABASE_PERMISSIONS P, SYS.OBJECTS O 
WHERE P.MAJOR_ID=O.OBJECT_ID AND P.STATE=''W''
IF @cnt = 0
	BEGIN
		PRINT ''No Results''
	END
ELSE
	BEGIN
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @name= user_name(P.GRANTEE_PRINCIPAL_ID)
			FROM SYS.DATABASE_PERMISSIONS P, SYS.OBJECTS O 
			WHERE P.MAJOR_ID=O.OBJECT_ID AND P.STATE=''W''
			PRINT ''With grant option : ''+@name
			SET @cnt = @cnt - 1
		END
	END
PRINT ''''
'
PRINT ' '
insert into @result(name) values('D-19 : 결과 확인 N/A')
PRINT ' '
PRINT '[CHECK] No Results가 출력되면 양호, 관리자 계정이외에 With grant option이 존재하면 취약 '
PRINT ' '
PRINT '[D-19] END'

PRINT '======================================================================='
PRINT '출력 결과를 참조하여 양호, 취약여부 판단'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-20] 데이터베이스의 자원 제한 기능을TRUE로 설정 '
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL은 전역 리소스를 통해 자원을 관리하기 때문에 해당사항 없음 '
PRINT ''
insert into @result(name) values('D-20 : N/A')
PRINT ' '
PRINT '[D-20] END'
PRINT '======================================================================='
PRINT 'MS-SQL은 해당사항 없음'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-21] 데이터베이스에 대해 최신 보안패치와 벤더 권고사항을 모두 적용 '
PRINT '======================================================================='
PRINT ''
SELECT SERVERPROPERTY('productversion') as Version, SERVERPROPERTY('productlevel') as 'Service Pack'
PRINT ''
PRINT '[CHECK] 벤더사의 최신 업데이트 패치 여부 확인 (최근 6개월 ~ 1년 이내의 패치가 존재하나 미 업데이트 시 취약) '
PRINT ''
PRINT '          ※ http://support.microsoft.com/kb/321185/en-us 참조'
PRINT ''
insert into @result(name) values('D-21 : 최신 업데이트 및 패치여부 확인')
PRINT ' '
PRINT '[D-21] END'
PRINT '======================================================================='
PRINT '벤더 홈페이지에 방문하여 각 서비스팩, RTM 버전별 최신패치를 확인 후 양호, 취약여부 판단 '
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-22] 데이터베이스의 접근, 변경, 삭제 등의 감사기록이 기관의 감사기록 정책에 적합하도록 설정 '
PRINT '======================================================================='
PRINT ''
PRINT '콘솔 확인 및 인터뷰 '
PRINT ' '
PRINT '1. MS-SQL Server에 대한 연결감사 설정 유무 확인 '
PRINT ''
PRINT '[CHECK] 시작 -> 모든 프로그램 -> Microsoft SQL Server 2005 or 2008 -> SQL Server Management Studio '
PRINT '        -> 개체 탐색기에서 서버 선택 -> 속성 메뉴 -> 보안 페이지 -> 로그인 감사 -> 설정유무 확인 (감사수준이 "실패한 로그인과 성공한 로그인 모두"로 선택되어 있으면 양호)'
PRINT ''
PRINT '2. 데이터베이스의 접근, 변경, 삭제 등의 감사기록 설정 유무 확인 '
PRINT ''
PRINT '[CHECK] ① MS-SQL 2008의 경우 SQL Server Management Studio를 통해 감사기록 설정을 할 수 있어 SQL Server Management Studio로 감사기록 설정상태를 확인할 수 있음 '
PRINT '          시작 -> 모든 프로그램 -> Microsoft SQL Server 2005 or 2008 -> SQL Server Management Studio '
PRINT '          -> 하위메뉴의 보안 선택 -> 하위메뉴의 감사 선택 -> 감사메뉴 하위에 데이터베이스의 접근, 변경, 삭제등의 감사기록 설정이 존재하는 지 확인 (미설정 시 취약) '
PRINT '        ② MS-SQL 2000, 2005의 경우 SQL Server Management Studio를 통해 확인이 어려워 담당자와 인터뷰를 통해  데이터베이스 감사기록, '
PRINT '          백업 정책 관련 지침이 존재하는지 확인 후 확인된 내용을 토대로 실제 감사기록 및 백업이 이루어지는지 확인이 필요함 '
PRINT ''
PRINT '          ※ DB 접근제어 솔루션과 같은 솔루션을 이용하여 감사기록이 수집되고 있을 시 양호로 판단함'

insert into @result(name) values('D-22 : 콘솔 확인 및 인터뷰')
PRINT ' '
PRINT '[D-22] END'
PRINT '======================================================================='
PRINT '인터뷰를 통해 데이터베이스 감사기록, 백업 정책관련 지침이 존재하는지 확인 '
PRINT '확인된 내용을 토대로 실제 감사 기록 및 백업이 이루어지는지 확인이 필요함 '
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-23] 보안에 취약하지 않은 버전의 데이터베이스 사용 '
PRINT '======================================================================='
PRINT ''
SELECT SERVERPROPERTY('productversion') as Version, SERVERPROPERTY('productlevel') as 'Service Pack'
PRINT ''
PRINT '[CHECK] 벤더사의 최신 업데이트 패치 여부 확인 (최근 6개월 ~ 1년 이내의 패치가 존재하나 미 업데이트 시 취약) '
PRINT ''
PRINT '          ※ http://support.microsoft.com/kb/321185/en-us 참조'
PRINT ''
insert into @result(name) values('D-23 : 최신 업데이트 및 패치여부 확인')
PRINT ' '
PRINT '[D-23] END'
PRINT '======================================================================='
PRINT 'D-21 진단결과와 동일하므로 참조 '
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-24] Audit Table이 데이터베이스 관리자 계정에 속하도록 설정 '
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL의 경우 Database의 Table이 아닌 Log File로 감사기록을 저장하고 로그뷰어를 통해 조회하기 때문에 해당사항 없음 '
PRINT ''
insert into @result(name) values('D-24 : N/A')
PRINT ' '
PRINT '[D-24] END'
PRINT '======================================================================='
PRINT 'MS-SQL은 해당사항 없음'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '========================================================================'
PRINT '############################## 결 과 취 합 #############################'
PRINT '========================================================================'
PRINT ' '

SELECT @cnt = COUNT(*) FROM @result
set @result_1 = 1
WHILE @cnt != 0
	begin
		select top(@result_1) @name=NAME FROM @result
		print @name
		set @result_1 = @result_1 + 1
		set @cnt = @cnt - 1
	end
print ''

```
