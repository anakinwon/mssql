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
PRINT '[D-1] �⺻������ �н�����, ��å ���� �����Ͽ� ���'
PRINT '      �� SA ���� �н����� ���� ���� ����'
PRINT '      �� ����� �н����� ��뿩�� ����'
PRINT '======================================================================='
PRINT '�� SA ���� �н����� ���� ���� ����'
PRINT ''
Select name, password from sys.syslogins where name='sa'

select @pass = ISNULL(password,0) from sys.syslogins where name='sa' group by password
IF @pass='0'
	BEGIN
			PRINT '���'
			insert into @result(name) values('D-1-�� : ���')
	END
ELSE
	PRINT '��ȣ'
	insert into @result(name) values('D-1-�� : ��ȣ')

PRINT ' '
PRINT '[CHECK] ��µ� ������ password�� NULL���� �����ϸ� ���'
PRINT ''
PRINT '�� ����� �н����� ��뿩�� ����'
PRINT ''
SELECT @cnt = count(NAME) FROM SYS.SYSLOGINS WHERE PWDCOMPARE(NAME,PASSWORD) = 1 
IF @cnt = 0
	BEGIN
		PRINT '������� ������ �н����带 ����ϴ� ������ �������� ����'
		PRINT ''
		PRINT '��ȣ'
		insert into @result(name) values('D-1-�� : ��ȣ')
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
		PRINT '���'
		insert into @result(name) values('D-1-�� : ���')
    END
    
PRINT ' '
PRINT '[CHECK] ��ȣ�� ��µǸ� ��ȣ�̸�, �������� ��µǸ� ������� ������ ����� �н����带 ����ϴ� ������ ��µ� ������ ���'

PRINT ' '
PRINT '[D-1] END'

PRINT '======================================================================='
PRINT '�� ���� �׸� ��� ��ȣ�� Ȯ�εǾ�� ��ȣ�� �Ǵ�'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-2] scott �� Demonstration �� ���ʿ� ������ �����ϰų� ��ݼ��� �� ���'
PRINT '      MS-SQL ���ܱ��ؿ� �����Ͽ� �Ʒ��׸��� ����'
PRINT '      �� ���ʿ��� ���� ���翩�� ����'
PRINT '      �� SA���� Disable ���� ����'
PRINT '      �� Guest���� Disable ���� ����'
PRINT '======================================================================='
PRINT '�� ���ʿ��� ���� ���翩�� ����'
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
			PRINT '������ : '+@name
			SET @cnt = @cnt - 1			
		END		
PRINT ''
PRINT '[CHECK] DBMS�� �����ϴ� ������ ��� ����� Ȯ�� �� ���ͺ�'

insert into @result2(value) values('D-2-�� ���� : ������ ���ȭ �Ͽ� ���� ���� �ʰ�, ���ʿ� ������ ���� �ϸ� ���')
insert into @result(name) values('D-2-�� : ��� Ȯ�� �� ���ͺ�')

PRINT ''
PRINT '�� SA���� Disable ���� ����'
PRINT ''
SELECT @dis = IS_DISABLED FROM SYS.SQL_LOGINS WHERE NAME='SA'
IF @dis = 1
	BEGIN
		PRINT 'Disable'
		PRINT ''
		PRINT '��ȣ'
		insert into @result(name) values('D-2-�� : ��ȣ')
	END
ELSE
	BEGIN
		PRINT 'Enable'
		PRINT ''
		PRINT '���'
		insert into @result(name) values('D-2-�� : ���')
	END
PRINT ''
PRINT '[CHECK] Disable ��½� ��ȣ, Enable��� �� ���'

PRINT ''
PRINT '�� Guest���� Disable ���� ����'
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
PRINT '[CHECK] ��ü Database�� �����ϴ� Guest���� Enable/Disable ���� Ȯ�� �� �Ǵ�'

insert into @result(name) values('D-2-�� : ��� Ȯ��')

PRINT ' '
PRINT '[D-2] END'

PRINT '======================================================================='
PRINT '�� ���� �׸� ��� ��ȣ�� Ȯ�εǾ�� ��ȣ�� �Ǵ�'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-3] �н������� ���Ⱓ �� ���⵵�� ����� ��å�� �µ��� ����'
PRINT '      MS-SQL ���ܱ��ؿ� �����Ͽ� �Ʒ��׸��� ����'
PRINT '      �� ��ȣ ���� ���� ���� ���� ����'
PRINT '      �� ��ȣ ��å ���� ���� ���� ����'
PRINT '======================================================================='
PRINT '�� ��ȣ ���� ���� ���� ���� ����'
PRINT ''
SELECT @cnt = count(NAME) FROM SYS.SQL_LOGINS WHERE IS_EXPIRATION_CHECKED=0
IF @cnt = 0
	BEGIN
		PRINT '�н����� �����ֱ⸦ �����ϰ� �����ϰ� ����'
		PRINT ' '
		PRINT '��ȣ'
		insert into @result(name) values('D-3-�� : ��ȣ')
	END
ELSE
    BEGIN
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @name= NAME FROM SYS.SQL_LOGINS WHERE IS_EXPIRATION_CHECKED=0 
			PRINT '������ : ' + @name
			SET @cnt = @cnt - 1
		END
		PRINT ' '
		PRINT '���'
		insert into @result(name) values('D-3-�� : ���')
    END
PRINT ' '
PRINT '[CHECK] ��ȣ ���� ���� ���� ������ ������ ������ ���ܰ���� ��µǸ� ���'
PRINT '        �� Windows���� ����� ���� DBMS � �� ���� ���'
PRINT '          * ���� -> ���� -> secpol.msc -> ���� ���� -> ���� ��å -> ��ȣ ��å �޴��� ���� ��å ���� ���� ���� (�ִ� ��ȣ ��� �Ⱓ Check - ����� �ǰ� 90��) '
PRINT '        �������� �����׸�[W-11]�н����� �ִ� ���Ⱓ �׸�����'
PRINT ''
PRINT '�� ��ȣ ��å ���� ���� ���� ����'
PRINT ''
SELECT @cnt = count(NAME) FROM SYS.SQL_LOGINS WHERE IS_POLICY_CHECKED=0
IF @cnt = 0
	BEGIN
		PRINT '��ȣ ��å�� ���� �����ϰ� ����'
		PRINT ' '
		PRINT '��ȣ'
		insert into @result(name) values('D-3-�� : ��ȣ')
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
		PRINT '���'
		insert into @result(name) values('D-3-�� : ���')
    END

PRINT ''
PRINT '[CHECK] ��ȣ ��å ���� ���� ������ ������ ������ ���ܰ���� ��µǸ� ���'
PRINT '        �� Windows���� ����� ���� DBMS � �� ���� ���'
PRINT '          * ���� -> ���� -> secpol.msc -> ���� ���� -> ���� ��å -> ��ȣ ��å �޴��� ���� ��å ���� ���� ���� (��ȣ�� ���⼺�� �����ؾ� �� Check - ��뿩��) '
PRINT '         �������� �����׸�[W-9] �н����� ���⼺ �����׸�����'
PRINT ' '
PRINT '[D-3] END'

PRINT '======================================================================='
PRINT '�� ���� ����� ������ �����Ͽ��� ��� Windows ���� ���ܰ�� ���� (W-9, W-11)'
PRINT '�� ���� �׸� ��� ��ȣ�� Ȯ�εǾ�� ��ȣ�� �Ǵ�'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-4] �����ͺ��̽� ������ ������ �� �ʿ��Ѱ��� �� �׷쿡 ���'
PRINT '======================================================================='

PRINT ' '
PRINT '- ������ ������ �����ִ� ���� ��� - '
PRINT ' '
SELECT @cnt = count(NAME) FROM SYS.server_principals A, sys.server_role_members B WHERE A.principal_id = B.MEMBER_principal_id AND role_principal_id =3
IF @cnt = 0
	BEGIN
		PRINT 'NOT Result'
		insert into @result(name) values('D-4 :	��ȣ')
		
	END
ELSE
	BEGIN
	WHILE 0 != @cnt
		BEGIN
			SELECT TOP (@cnt) @name= NAME 
			FROM SYS.server_principals A, sys.server_role_members B 
			WHERE A.principal_id = B.MEMBER_principal_id AND role_principal_id =3
			ORDER BY name
			PRINT '������ : ' + @name
			SET @cnt = @cnt - 1
			
		END
	END
PRINT ''
insert into @result(name) values('D-4 :	��� Ȯ�� �� ���ͺ�')
PRINT ''
PRINT '[CHECK] �����ڰ� �ƴ� ����ڿ��� DBA������ �ο��Ǿ� ������� ���, ���Ȯ�� �� ���ͺ� �ʿ�'

PRINT ' '
PRINT '[D-4] END'
PRINT '======================================================================='
PRINT 'SA, SYSTEM, Windows ������ ���� SQL Server �α��� ������ ����'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-5] �н����� ���� ���� ����'
PRINT '======================================================================='
PRINT ' '
PRINT '�ܼ� Ȯ�� '
insert into @result(name) values('D-5 :	�ܼ� Ȯ��')
PRINT ''
PRINT '[CHECK] Windows ������ ���� �α��� ����� ����ؾ� ���ܰ���/�̻�� �� �ش���� ����'
PRINT '        �� Windows���� ����� ���� DBMS � �� ���� ���'
PRINT '          * ���� -> ���� -> secpol.msc -> ���� ���� -> ���� ��å -> ��ȣ ��å �޴��� ���� ��å ���� ���� ���� (�ֱ� ��ȣ ��� Check - 5�� �̻�) '
PRINT '         �������� �����׸�[W-16] �ֱ� ��ȣ ����׸� ����'

PRINT ' '
PRINT '[D-5] END'
PRINT '======================================================================='
PRINT '�� ���� ����� ������ �����Ͽ��� ��� Windows ���� ���ܰ�� ���� (W-16)'
PRINT '�ֱ� ��ȣ ��� ������ ���� ������ ����ϴ� �н������ ���ο� �н������ ������ �Ұ����ϰ� ����'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-6] DB ����� ������ ���������� �ο�'
PRINT '======================================================================='
PRINT ' '
PRINT '1. ����� �� ���� ���� üũ'
PRINT ' ���� : Class : Database : Permission : Protocol'
PRINT ''

-- ���� �� ���� ���� üũ
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

PRINT '2. Database �� ����� Role ���� üũ'
PRINT '���� : ����(Role)'
PRINT ''
-- ROLE üũ
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
insert into @result(name) values('D-6 :	��� Ȯ�� �� ���ͺ�')

PRINT ''
PRINT '[CHECK] �������� �����ͺ��̽��� ���� ���Ҹ��(Database role)�� Ȯ���Ͽ� �ʿ��̻��� ������ �־��� �ִ��� Ȯ��'

PRINT ' '
PRINT '[D-6] END'
PRINT '======================================================================='
PRINT '1, 2�� ��°���� �����Ͽ� ����ڿ� ���ͺ並 ���� �Ǵ��ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-7] ���ݿ��� DB�������� ���� ����'
PRINT '======================================================================='
PRINT ' '
PRINT '�ܼ� Ȯ�� '
insert into @result(name) values('D-7 :	�ܼ� Ȯ��')
PRINT ''
PRINT '[CHECK] ���� -> ��� ���α׷� -> Microsoft SQL Server 2005 or 2008 -> ���� ���� -> SQL Server ���� ������ '
PRINT '        -> SQL Server ��Ʈ��ũ ���� -> TCP/IP -> IP �ּ� -> TCP ��Ʈ Ȯ�� (Default Port 1433 ����)'
PRINT ''
PRINT '          �� Default TCP 1433 Port�� ������̸� ����ϳ� OS ��ü ��ȭ�� �Ǵ� ��ȭ��, DB�������� �ý��۵�� ���� ������� ���� ����� IP�� ���ؼ��� �������� ������ �ϰ����� ��� ��ȣ'
PRINT '          Windows ��ũ��Ʈ����� 73���� Active Connections LISTEN ��Ʈ����Ʈ Ȯ��'

PRINT ' '
PRINT '[D-7] END'
PRINT '======================================================================='
PRINT '�ܼ��� ���� �������� ���� Ȯ�ΰ� ����ڿ� ���ͺ並 ���� �Ǵ��ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-8] DBA �̿��� �ΰ����� ���� ����� �ý��� ���̺� ���� ���� ����'
PRINT '======================================================================='
PRINT ' '
PRINT '- Object�� �����ѿ� Public Role�� �ο��� �ý��� ���̺� ��� -'
PRINT ''
select U.name as [PRINCIPAL], T.name as [TABLE], P.permission_name as [PERMISSION],
P.state_desc as [STATE]
from sys.database_principals U
join sys.database_permissions P on U.principal_id=P.grantee_principal_id
join sys.tables T on P.major_id=T.object_id
where P.state_desc<>'DENY' and T.is_ms_shipped=1 order by U.name, T.name
PRINT ''
PRINT '[CHECK] ��µ� ���̺���� Public Role �ο��� ������ ���������� ����Ʈ ���� ȯ���� Ư���� ���� '
PRINT '        Public Role�� ����� �� �ֱ� ������ ����ڿ� ���ͺ� �� ��ȣ, ��� ���θ� �Ǵ��ؾ� ��'
PRINT ''
PRINT '          �� ����ϴٰ� �ǴܵǾ� ��ġ �ǰ� �� ������ �߻��� �� �ֱ� ����'

PRINT ''
insert into @result(name) values('D-8 :	��� Ȯ�� �� ���ͺ�')
       
PRINT ' '
PRINT '[D-8] END'
PRINT '======================================================================='
PRINT '��� ����� �����Ͽ� ����ڿ� ���ͺ並 ���� �Ǵ��ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-9] ����Ŭ �����ͺ��̽��� ��� ������ �н����� ����'
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL�� �ش���� ���� '
PRINT ''
insert into @result(name) values('D-9 : N/A')
PRINT ' '
PRINT '[D-9] END'
PRINT '======================================================================='
PRINT '�ܼ��� ���� ���������� Ȯ���ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-10] ���ʿ��� ODBC/OLE-DB ������ �ҽ��� ����̺� ����'
PRINT '======================================================================='
PRINT ''
PRINT '�ܼ� Ȯ�� '
PRINT ' '
PRINT '[CHECK] ���� -> ���� -> ������ -> �������� -> ������ ���� (ODBC) -> �ý���DSN -> ���ʿ��� ODBC/OLE-DB ������ �ҽ��� ����̺� Ȯ�� '
PRINT ''
PRINT '          �� ���� ����� ������ �����Ͽ��� ��� [W-52] ���ʿ��� ODBC/OLE-DB ������ �ҽ��� ����̺� �����׸� ����'
PRINT ' '
insert into @result(name) values('D-10 : �ܼ� Ȯ��')
PRINT ' '
PRINT '[D-10] END'
PRINT '======================================================================='
PRINT '�ܼ��� ���� ���������� Ȯ���ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-11] ���� Ƚ���� �α��� ���н� �̿� ���� �����å ���� '
PRINT '======================================================================='
PRINT ''
PRINT '�ܼ� Ȯ�� '
PRINT ' '
PRINT '[CHECK] ���� -> ���� -> secpol.msc -> ���� ���� -> ���� ��å -> ���� ��� ��å -> ���� ��� �Ӱ谪 Ȯ�� (3ȸ �̻�) '
PRINT ''
PRINT '          �� ���� ����� ������ �����Ͽ��� ��� Windows ���� ���ܰ�� ���� (W-04, W-08)'
PRINT '          �� ���� ��� �Ӱ谪�� 3ȸ �̻�, ���� ��� �Ⱓ�� 60�� �̻����� �����Ǿ� ���� �� ��ȣ, �� ���� �� ���, Windows ���� ����� ����ϰ� ���� ���� ��쵵 ���'
PRINT ' '
insert into @result(name) values('D-11 : N/A')
PRINT ' '
PRINT '[D-11] END'
PRINT '======================================================================='
PRINT '�ܼ��� ���� ���������� Ȯ���ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-12] �����ͺ��̽��� �ֿ� ���� ��ȣ ���� ���� DB ������ umask�� 022 �̻����� ���� '
PRINT '       MS-SQL ���ܱ��ؿ� �����Ͽ� �Ʒ��׸��� ����'
PRINT '       SQL Server ������ ���͸��� ������ ���� ���(ACL)�� �����ϰ� �����Ǿ� �ִ��� ����'
PRINT '======================================================================='
PRINT ''
PRINT '�ܼ� Ȯ�� '
PRINT ' '
PRINT '1. �����ͺ��̽��� ���� ���͸� ��θ� Ȯ�� '
PRINT ''
select DB_NAME(database_id) as 'Database', name, physical_name from sys.master_files
PRINT ''
PRINT '2. �� ��°������ Ȯ�ε� ����� ACL�� �����ϰ� �����Ǿ� �ִ��� Ȯ�� '
PRINT ''
PRINT 'Ȯ�ε� ����� ex> - Program Files\Microsoft SQL Server\MSSQL$InstanceName\Binn'
PRINT '                - Program Files\Microsoft SQL Server\MSSQL$InstanceName\Data'
PRINT '                - Program Files\Microsoft SQL Server\MSSQL$InstanceName\LOG'
PRINT '                - Program Files\Microsoft SQL Server\MSSQL$InstanceName\Backup ���� ��ο� ����'
PRINT 'SQL Server service accounts �� local Administrators ������ ���� �����ϵ��� �����Ǿ� �ִ��� Ȯ��'
PRINT ''
PRINT '[CHECK] Everyone:(F)�� ���� �����ϰ� �� �ʿ��� ���Ѹ� �ο��Ͽ����� Ȯ�� '
PRINT ' '
insert into @result(name) values('D-12 : �ܼ� Ȯ�� N/A')
PRINT ' '
PRINT '[D-12] END'
PRINT '======================================================================='
PRINT '�ܼ��� ���� ���������� Ȯ���ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-13] �����ͺ��̽��� �ֿ� ��������, �н����� ���� ��� ���� �ֿ� ���ϵ��� ���ٱ��� ���� '
PRINT '======================================================================='
PRINT ''
PRINT '�ܼ� Ȯ�� '
PRINT ' '
PRINT '[CHECK] D-12�� ���ܰ���� ��ȣ, ��࿩�� �Ǵ� ���� '
PRINT ''
insert into @result(name) values('D-13 : �ܼ� Ȯ��')
PRINT ''
PRINT '[D-13] END'
PRINT '======================================================================='
PRINT 'D-12�� ���ܰ�� Ȯ�� �� �Ǵ�'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-14] ������ �̿��� ����ڰ� ����Ŭ �������� ������ ���� ������ �α� �� trace ���Ͽ� ���� ���� ���� '
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL�� �ش���� ���� '
PRINT ''
insert into @result(name) values('D-14 : N/A')
PRINT ''
PRINT '[D-14] END'
PRINT '======================================================================='
PRINT 'MS-SQL�� �ش���� ����'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-15] ���� ���α׷� �Ǵ� DBA ������ Role�� Public���� �������� �ʵ��� ���� '
PRINT '======================================================================='
PRINT ''
PRINT '�ܼ� Ȯ�� '
PRINT ' '
PRINT '[CHECK] ���� -> ��� ���α׷� -> Microsoft SQL Server 2005 or 2008 -> SQL Server Management Studio '
PRINT '        -> ��ü Ž���⿡�� ���� ���� -> �����޴��� ���� ���� -> �����޴��� �α��� ���� (�������� ���� Role�μ� ���Ѻο� ���� Ȯ�� ����) '
PRINT '        -> ������ �Ӽ� �޴� -> ���� ��ü ������ -> �˻� ��ư -> ���� ''�ν��Ͻ� ����'' -> Role�μ� ������ �ο��ϰ� �ִ��� ���� Ȯ�� '
PRINT ''
PRINT '          �� ��������� ������ �ο��ϴ� ��� ���, �� ����� ���� �ο����� �� ''SQL ����'' ������ ����'
PRINT ' '
SELECT user_name(p.grantee_principal_id) 'User', o.name 'Object',p.permission_name 
FROM sys.objects o, sys.database_permissions p
WHERE o.object_id=p.major_id AND p.grantee_principal_id in(0,2)
insert into @result(name) values('D-15 : �ܼ� Ȯ��')
PRINT ' '
PRINT '[D-15] END'
PRINT '======================================================================='
PRINT '�ܼ��� ���� ���������� Ȯ���ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-16] OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES�� FALSE�� ���� '
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL�� �ش���� ���� '
PRINT ''
insert into @result(name) values('D-16 : N/A')
PRINT ' '
PRINT '[D-16] END'

PRINT '======================================================================='
PRINT '�� ���� �׸� ��� ��ȣ�� Ȯ�εǾ�� ��ȣ�� �Ǵ�'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-17] �н����� Ȯ���Լ� ���� '
PRINT '======================================================================='
PRINT ''
PRINT '�ܼ� Ȯ�� '
PRINT ' '
PRINT '[CHECK] Windows ��������� ��� �� Windows�� ���� ��å�� ����ޱ� ������ D-03 ���ܰ�� �н����� ���⼺ ������ �Ǿ� �ִٸ� ��ȣ�� �Ǵ��� '
PRINT ''
SELECT name, is_disabled FROM sys.sql_logins WHERE type='S' AND is_policy_checked <> '1' 
insert into @result(name) values('D-17 : �ܼ� Ȯ�� N/A')
PRINT ' '
PRINT '[D-17] END'
PRINT '======================================================================='
PRINT 'D-03�� ���ܰ�� Ȯ�� �� �Ǵ�'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-18] �ΰ����� ���� Object Owner�� ���� ���� '
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
		PRINT '��ȣ'
		insert into @result(name) values('D-18 : ��ȣ')
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
			PRINT @TYPE + ' : '+ STR(@cnt_1)+ '��'
			SET	@cnt = @cnt - 1
		END
		PRINT ''
		PRINT '��� Ȯ�� �� ���ͺ�'
		insert into @result(name) values('D-18 : ��� Ȯ�� �� ���ͺ�')
    END
PRINT ' '
PRINT '[CHECK] No Results�� ��µǸ� ��ȣ, '
PRINT '        ��µ� ���̺���� Public Role �ο��� ������ ���������� ����Ʈ ���� ȯ���� Ư���� ���� '
PRINT '        Public Role�� ����� �� �ֱ� ������ ����ڿ� ���ͺ� �� ��ȣ, ��� ���θ� �Ǵ��ؾ� ��'
PRINT ''
PRINT '          �� ����ϴٰ� �ǴܵǾ� ��ġ �ǰ� �� ������ �߻��� �� �ֱ� ����'

PRINT ''
PRINT '[D-18] END'

PRINT '======================================================================='
PRINT 'GUEST�� PUBLIC �������� ���� ������ Object Group�� Object ������ ��µǸ� ����ڿ� ���ͺ並 ���� ��� ���θ� �Ǵ��ؾ� ��'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-19] grant option�� role�� ���� �ο��ǵ��� ���� '
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
insert into @result(name) values('D-19 : ��� Ȯ�� N/A')
PRINT ' '
PRINT '[CHECK] No Results�� ��µǸ� ��ȣ, ������ �����̿ܿ� With grant option�� �����ϸ� ��� '
PRINT ' '
PRINT '[D-19] END'

PRINT '======================================================================='
PRINT '��� ����� �����Ͽ� ��ȣ, ��࿩�� �Ǵ�'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-20] �����ͺ��̽��� �ڿ� ���� �����TRUE�� ���� '
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL�� ���� ���ҽ��� ���� �ڿ��� �����ϱ� ������ �ش���� ���� '
PRINT ''
insert into @result(name) values('D-20 : N/A')
PRINT ' '
PRINT '[D-20] END'
PRINT '======================================================================='
PRINT 'MS-SQL�� �ش���� ����'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-21] �����ͺ��̽��� ���� �ֽ� ������ġ�� ���� �ǰ������ ��� ���� '
PRINT '======================================================================='
PRINT ''
SELECT SERVERPROPERTY('productversion') as Version, SERVERPROPERTY('productlevel') as 'Service Pack'
PRINT ''
PRINT '[CHECK] �������� �ֽ� ������Ʈ ��ġ ���� Ȯ�� (�ֱ� 6���� ~ 1�� �̳��� ��ġ�� �����ϳ� �� ������Ʈ �� ���) '
PRINT ''
PRINT '          �� http://support.microsoft.com/kb/321185/en-us ����'
PRINT ''
insert into @result(name) values('D-21 : �ֽ� ������Ʈ �� ��ġ���� Ȯ��')
PRINT ' '
PRINT '[D-21] END'
PRINT '======================================================================='
PRINT '���� Ȩ�������� �湮�Ͽ� �� ������, RTM ������ �ֽ���ġ�� Ȯ�� �� ��ȣ, ��࿩�� �Ǵ� '
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-22] �����ͺ��̽��� ����, ����, ���� ���� �������� ����� ������ ��å�� �����ϵ��� ���� '
PRINT '======================================================================='
PRINT ''
PRINT '�ܼ� Ȯ�� �� ���ͺ� '
PRINT ' '
PRINT '1. MS-SQL Server�� ���� ���ᰨ�� ���� ���� Ȯ�� '
PRINT ''
PRINT '[CHECK] ���� -> ��� ���α׷� -> Microsoft SQL Server 2005 or 2008 -> SQL Server Management Studio '
PRINT '        -> ��ü Ž���⿡�� ���� ���� -> �Ӽ� �޴� -> ���� ������ -> �α��� ���� -> �������� Ȯ�� (��������� "������ �α��ΰ� ������ �α��� ���"�� ���õǾ� ������ ��ȣ)'
PRINT ''
PRINT '2. �����ͺ��̽��� ����, ����, ���� ���� ������ ���� ���� Ȯ�� '
PRINT ''
PRINT '[CHECK] �� MS-SQL 2008�� ��� SQL Server Management Studio�� ���� ������ ������ �� �� �־� SQL Server Management Studio�� ������ �������¸� Ȯ���� �� ���� '
PRINT '          ���� -> ��� ���α׷� -> Microsoft SQL Server 2005 or 2008 -> SQL Server Management Studio '
PRINT '          -> �����޴��� ���� ���� -> �����޴��� ���� ���� -> ����޴� ������ �����ͺ��̽��� ����, ����, �������� ������ ������ �����ϴ� �� Ȯ�� (�̼��� �� ���) '
PRINT '        �� MS-SQL 2000, 2005�� ��� SQL Server Management Studio�� ���� Ȯ���� ����� ����ڿ� ���ͺ並 ����  �����ͺ��̽� ������, '
PRINT '          ��� ��å ���� ��ħ�� �����ϴ��� Ȯ�� �� Ȯ�ε� ������ ���� ���� ������ �� ����� �̷�������� Ȯ���� �ʿ��� '
PRINT ''
PRINT '          �� DB �������� �ַ�ǰ� ���� �ַ���� �̿��Ͽ� �������� �����ǰ� ���� �� ��ȣ�� �Ǵ���'

insert into @result(name) values('D-22 : �ܼ� Ȯ�� �� ���ͺ�')
PRINT ' '
PRINT '[D-22] END'
PRINT '======================================================================='
PRINT '���ͺ並 ���� �����ͺ��̽� ������, ��� ��å���� ��ħ�� �����ϴ��� Ȯ�� '
PRINT 'Ȯ�ε� ������ ���� ���� ���� ��� �� ����� �̷�������� Ȯ���� �ʿ��� '
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-23] ���ȿ� ������� ���� ������ �����ͺ��̽� ��� '
PRINT '======================================================================='
PRINT ''
SELECT SERVERPROPERTY('productversion') as Version, SERVERPROPERTY('productlevel') as 'Service Pack'
PRINT ''
PRINT '[CHECK] �������� �ֽ� ������Ʈ ��ġ ���� Ȯ�� (�ֱ� 6���� ~ 1�� �̳��� ��ġ�� �����ϳ� �� ������Ʈ �� ���) '
PRINT ''
PRINT '          �� http://support.microsoft.com/kb/321185/en-us ����'
PRINT ''
insert into @result(name) values('D-23 : �ֽ� ������Ʈ �� ��ġ���� Ȯ��')
PRINT ' '
PRINT '[D-23] END'
PRINT '======================================================================='
PRINT 'D-21 ���ܰ���� �����ϹǷ� ���� '
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '======================================================================='
PRINT '[D-24] Audit Table�� �����ͺ��̽� ������ ������ ���ϵ��� ���� '
PRINT '======================================================================='
PRINT ''
PRINT 'N/A '
PRINT ' '
PRINT '[CHECK] MS-SQL�� ��� Database�� Table�� �ƴ� Log File�� �������� �����ϰ� �α׺� ���� ��ȸ�ϱ� ������ �ش���� ���� '
PRINT ''
insert into @result(name) values('D-24 : N/A')
PRINT ' '
PRINT '[D-24] END'
PRINT '======================================================================='
PRINT 'MS-SQL�� �ش���� ����'
PRINT '======================================================================='

PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '
PRINT ' '

PRINT '========================================================================'
PRINT '############################## �� �� �� �� #############################'
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