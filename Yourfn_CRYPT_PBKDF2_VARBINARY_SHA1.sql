USE tempdb; -- in case YourDB does not exist
USE YourDB;
GO

IF EXISTS (SELECT * FROM dbo.sysobjects WHERE id = object_id(N'[dbo].[Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1]') AND xtype IN (N'FN', N'IF', N'TF'))
DROP FUNCTION [dbo].[Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1]
GO

CREATE FUNCTION [dbo].[Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1]
  (
  @Password VARBINARY(4000), -- HASHBYTES is limited, and HMAC concatenation limits this more, though 4000 is a guess
  @Salt VARBINARY(4000), -- HASHBYTES is limited, and HMAC concatenation limits this more, though 4000 is a guess
  @IterationCount INT,
  @Outputbytes INT -- For password hashing, should "naturally" be the digest size (or less) - more than the digest size allows the first <digest size> to remain identical, so someone cracking the PBKDF2'd passwords only needs to generate and check the first <digest size>
  )
RETURNS VARBINARY(8000)
AS
BEGIN
-- SEE PKCS #5, RFC2989, as well as PBKDF2, i.e. http://tools.ietf.org/rfc/rfc2898.txt
-- WARNING - SQL is NOT a good language for this type of math; results are horrifically slow, and are better off being implemented
--   by another language.
-- This is a dedicated HMAC-SHA-1 version, with a moderate amount of performance tuning.

/*
--Normal test vectors
SET NOCOUNT ON
DECLARE @Result VARBINARY(4000)
DECLARE @start DATETIME2(7)
SET @start = SYSDATETIME()

PRINT 'RFC6070 Test 1'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'),CONVERT(VARBINARY(4000),'salt'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x0c60c80f961f0e71f3a9b524af6012062fe037a6 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC6070 Test 2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'),CONVERT(VARBINARY(4000),'salt'),2,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC6070 Test 3'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'),CONVERT(VARBINARY(4000),'salt'),4096,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x4b007901b765489abead49d926f721d065a429c1 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC6070 Test 4'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passwordPASSWORDpassword'),CONVERT(VARBINARY(4000),'saltSALTsaltSALTsaltSALTsaltSALTsalt'),4096,25)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC6070 Test 5'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'pass'+char(0)+'word'),CONVERT(VARBINARY(4000),'sa'+char(0)+'lt'),4096,16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x56fa6aa75548099dcc37d7f03425e0c3 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END


--NOT WORKING --PRINT 'Crypto++ 5.6.2 Test 1    from OpenSSL PKCS#12 Program FAQ v1.77, at http://www.drh-consultancy.demon.co.uk/test.txt'
--NOT WORKING --SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),0x0073006D006500670000),CONVERT(VARBINARY(4000),0x0A58CF64530D823F),1,24)
--NOT WORKING --SELECT @Result
--NOT WORKING --PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x8AAAE6297B6CB04642AB5B077851284EB7128F1A2A7FBCA3 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END


PRINT 'RFC3962 Test 1'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'),CONVERT(VARBINARY(4000),'ATHENA.MIT.EDUraeburn'),1,16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xcdedb5281bb2f801565a1122b2563515 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 1a and PERL ARODLAND Test Vector 1 raeburn 1 iter, 128-bit  http://www.ietf.org/rfc/rfc3962.txt http://tools.ietf.org/rfc/rfc3962.txt   or    http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.131750/t/01-raeburn.t'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'), CONVERT(VARBINARY(4000),'ATHENA.MIT.EDUraeburn'),1, 16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xcdedb5281bb2f801565a1122b2563515 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 1b and PERL ARODLAND Test Vector 2 raeburn 1 iter, 256-bit   http://tools.ietf.org/rfc/rfc3962.txt   or    http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.131750/t/01-raeburn.t'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'),CONVERT(VARBINARY(4000),'ATHENA.MIT.EDUraeburn'), 1, 32)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xcdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 2a PERL ARODLAND Test Vector 3 raeburn 2 iter, 128-bit   http://tools.ietf.org/rfc/rfc3962.txt   or    http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.131750/t/01-raeburn.t'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'),CONVERT(VARBINARY(4000),'ATHENA.MIT.EDUraeburn'),2, 16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x01dbee7f4a9e243e988b62c73cda935d THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 2b PERL ARODLAND Test Vector 4 raeburn 2 iter, 256-bit   http://tools.ietf.org/rfc/rfc3962.txt   or    http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.131750/t/01-raeburn.t'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1( CONVERT(VARBINARY(4000),'password'),CONVERT(VARBINARY(4000),'ATHENA.MIT.EDUraeburn'),2, 32)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 3a PERL ARODLAND Test Vector 5 raeburn 1200 iter, 128-bit   http://tools.ietf.org/rfc/rfc3962.txt   or    http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.131750/t/01-raeburn.t'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'), CONVERT(VARBINARY(4000),'ATHENA.MIT.EDUraeburn'), 1200, 16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x5c08eb61fdf71e4e4ec3cf6ba1f5512b THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 3b PERL ARODLAND Test Vector 6 raeburn 1200 iter, 256-bit   http://tools.ietf.org/rfc/rfc3962.txt   or    http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.131750/t/01-raeburn.t'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'), CONVERT(VARBINARY(4000),'ATHENA.MIT.EDUraeburn'),1200, 32)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 4a raeburn 5 iter, 128-bit   http://tools.ietf.org/rfc/rfc3962.txt'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'), CONVERT(VARBINARY(4000),0x1234567878563412),5, 16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xd1daa78615f287e6a1c8b120d7062a49 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 4b raeburn 5 iter, 256-bit   http://tools.ietf.org/rfc/rfc3962.txt'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'), CONVERT(VARBINARY(4000),0x1234567878563412),5, 32)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xd1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee THEN 'PASS' ELSE 'FAIL INVALID RESULT' END


PRINT 'RFC3962 Test 5a raeburn pass phrase equals block size, 128-bit   http://tools.ietf.org/rfc/rfc3962.txt'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1( CONVERT(VARBINARY(4000),'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'), CONVERT(VARBINARY(4000),'pass phrase equals block size'),1200, 16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x139c30c0966bc32ba55fdbf212530ac9 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END


PRINT 'RFC3962 Test 5b PERL ARODLAND Test Vector 7 raeburn pass phrase equals block size, 256-bit   http://tools.ietf.org/rfc/rfc3962.txt   or    http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.131750/t/01-raeburn.t'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1( CONVERT(VARBINARY(4000),'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'), CONVERT(VARBINARY(4000),'pass phrase equals block size'),1200, 32)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'RFC3962 Test 6a raeburn pass phrase exceeds block size, 128-bit   http://tools.ietf.org/rfc/rfc3962.txt'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1( CONVERT(VARBINARY(4000),'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'), CONVERT(VARBINARY(4000),'pass phrase exceeds block size'),1200, 16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x9ccad6d468770cd51b10e6a68721be61 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END


PRINT 'RFC3962 Test 6b PERL ARODLAND Test Vector 8 raeburn pass phrase exceeds block size, 256-bit   http://tools.ietf.org/rfc/rfc3962.txt   or    http://cpansearch.perl.org/src/ARODLAND/Crypt-PBKDF2-0.131750/t/01-raeburn.t'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1( CONVERT(VARBINARY(4000),'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'), CONVERT(VARBINARY(4000),'pass phrase exceeds block size'),1200, 32)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a THEN 'PASS' ELSE 'FAIL INVALID RESULT' END



PRINT 'RFC3962 Test 7a raeburn 50 iter, 128-bit g-clef turns into 4 characters   http://tools.ietf.org/rfc/rfc3962.txt'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1( CONVERT(VARBINARY(4000),0xf09d849e), CONVERT(VARBINARY(4000),'EXAMPLE.COMpianist'),50, 16)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x6b9cf26d45455a43a5b8bb276a403b39 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END


PRINT 'RFC3962 Test 7b raeburn 50 iter, 256-bit g-clef turns into 4 characters  http://tools.ietf.org/rfc/rfc3962.txt'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1( CONVERT(VARBINARY(4000),0xf09d849e), CONVERT(VARBINARY(4000),'EXAMPLE.COMpianist'),50, 32)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END


PRINT 'Long Test 1a 1 iter Len19pw Len19sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTT'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x6E8649FEC99424DB7B9C09886D0D97D17331322A THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 1b 100000 iter Len19pw Len19sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTT'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xB493A1CBADF50C765D08E54D18803432DB64CB05 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 2a 1 iter Len20pw Len20sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTl'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xDE91B0C83A8D960435E87A84BCB814A91B74377D THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 2b 100000 iter Len20pw Len20sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTl'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x7E80D79B5EFD106F4A0B9686DCDD6B62C29C9EAD THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 3a 1 iter Len21pw Len21sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlR'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2P'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xA24F5A4B1D572CF621A8DB8E9DF981516EF55F50 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 3b 100000 iter Len21pw Len21sa- validated against and a Javascript Python implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlR'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2P'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xA2EE2EA32951FE7C6FF2BABAF596EB0250FC4BBE THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 4a 1 iter Len63pw Len63sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xC547816C4421C0E96629606162F02B84D92748A3 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 4b 100000 iter Len63pw Len63sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE5'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJe'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xC8123940F4F09E4B541D499DEE5EF1ECD2E0959C THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 5a 1 iter Len64pw Len64sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x635EC6004FFBC14BF455F7E809BC8ED61296523A THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 5b 100000 iter Len64pw Len64sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJem'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x9F496882EEE86EF1B345D8CA6DD114C1837AE202 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 6a 1 iter Len65pw Len65sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x9C6386C4EBA9341F3D7866BDE76551FECEECE3EE THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 6b 100000 iter Len65pw Len65sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57U'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemk'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xE7E9C5B7234BD83BC726A4E4A5E71E633E2655BA THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 7a 1 iter Len127pw Len127sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x7045305766F689E8BD2D4AACC9E8F5BACD8003EA THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 7b 100000 iter Len127pw Len127sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi0'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xA29022FA638CAF09892CE9290AEA421060290D80 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 8a 1 iter Len128pw Len128sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x4E04E838D842DFC81E388CFA7D569B85025A7BEB THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 8b 100000 iter Len128pw Len128sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xB9137466D7E4886D1FDD270ACA25EF4E4604C681 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 9a 1 iter Len129pw Len129sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P'),1,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0x93B41369B60FB4F180DDD0C6CE230CACE6B58FC5 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

PRINT 'Long Test 9b 100000 iter Len129pw Len129sa- validated against a Python and a Javascript implemenation of PBKDF2'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'passDATAb00AB7YxDTTlRH2dqxDx19GDxDV1zFMz7E6QVqKIzwOtMnlxQLttpE57Un4u12D2YD7oOPpiEvCDYvntXEe4NNPLCnGGeJArbYDEu6xDoCfWH6kbuV6awi04U'),CONVERT(VARBINARY(4000),'saltKEYbcTcXHCBxtjD2PnBh44AIQ6XUOCESOhXpEp3HrcGMwbjzQKMSaf63IJemkURWoqHusIeVB8Il91NjiCGQacPUu9qTFaShLbKG0Yj4RCMV56WPj7E14EMpbxy6P'),100000,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xB069DE9CC16E9CA0F11857C8D35069EC4E78EDA8 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END
PRINT 'Duration (ms): ' + CONVERT(VARCHAR(23),DATEDIFF(ms,@start,SYSDATETIME()))



--*********************************************************
--*********************************************************
--****   The following tests are VERY slow             ****
--*********************************************************
--*********************************************************

--SLOW test vector
-- Takes ~79 seconds on a 2010 vintage machine.
SET NOCOUNT ON
DECLARE @Result VARBINARY(64)
PRINT 'RFC6070 Test 6 SLOW'
SET @Result = YourDB.dbo.Yourfn_CRYPT_PBKDF2_VARBINARY_SHA1(CONVERT(VARBINARY(4000),'password'),CONVERT(VARBINARY(4000),'salt'),16777216,20)
SELECT @Result
PRINT CASE WHEN @Result IS NULL THEN 'NULL - BAD ALGO?' WHEN @Result = 0xeefe3d61cd4da4e4e9945b3d6ba2158c2634e984 THEN 'PASS' ELSE 'FAIL INVALID RESULT' END

*/

  DECLARE @NumDigestSizesRequiredToEncompassOutputbytes INT
  DECLARE @RemainderOutputbytesAfterNumDigestSizesMinusOne INT
  DECLARE @Working BINARY(20) -- digest size
  DECLARE @ThisIterationResult BINARY(20) -- digest size
  DECLARE @FirstIterationDefinedResult VARBINARY(4004) -- Salt size + INT size per HMAC definition
  DECLARE @output VARBINARY(8000)
  DECLARE @CurrentDigestSizeChunk INT
  DECLARE @CurrentIteration INT
  -- Start Inlined HMAC-SHA-1 variables
  DECLARE @ipadRFC2104 BIGINT
  DECLARE @opadRFC2104 BIGINT
  DECLARE @k_ipadRFC2104 BINARY(64) -- BLOCKSIZE per HMAC definition
  DECLARE @k_opadRFC2104 BINARY(64) -- BLOCKSIZE per HMAC definition
  --SQL 2005 fails to allow binary operations on two binary data types!!!  We use bigint and interate 8 times for 512 bits = 64 bytes
  SET @ipadRFC2104 = CAST(0x3636363636363636 AS BIGINT)
  SET @opadRFC2104 = CAST(0x5C5C5C5C5C5C5C5C AS BIGINT)
  -- End Inlined HMAC-SHA-1 variables  

  SET @NumDigestSizesRequiredToEncompassOutputbytes = (@Outputbytes + 19)/20 -- number > 1 is digest size/digest size minus 1
  SET @RemainderOutputbytesAfterNumDigestSizesMinusOne = @Outputbytes - (@NumDigestSizesRequiredToEncompassOutputbytes - 1) * 20 -- number > 1 is digest size


  SET @output = 0x
  SET @CurrentDigestSizeChunk = 1

  WHILE @CurrentDigestSizeChunk <= @NumDigestSizesRequiredToEncompassOutputbytes
  BEGIN
    SET @FirstIterationDefinedResult = @Salt + CAST(@CurrentDigestSizeChunk AS VARBINARY(4))
    --SET @ThisIterationResult = YourDB.dbo.Yourfn_CRYPT_HMAC_SHA1(@Password,@FirstIterationDefinedResult)

    -- NOTE: Inlining HMAC-SHA-512 appears to improve performance by a factor of six or so.  Setting the HMAC as an Inlined Table Valued Function instead of a Scalar function would reduce this disparity, of course.
    -- START INLINED HMAC-SHA-512 for performance improvement
    -- B = BLOCKSIZE (64 bytes for MD5, SHA1, SHA-256, and 128 bytes for SHA-384 and SHA-512, per RFC2104 and RFC4868)
    IF LEN(@Password) > 64 -- Applications that use keys longer than B bytes will first hash the key using H and then use the resultant L byte string as the actual key to HMAC 
      SET @Password = CAST(HASHBYTES('SHA1', @Password) AS BINARY (64))
    ELSE
      SET @Password = CAST(@Password AS BINARY (64)) -- append zeros to the end of K to create a B byte string

    -- Loop unrolled for definite performance benefit
    -- Must XOR BLOCKSIZE bytes
    SET @k_ipadRFC2104 = CONVERT(BINARY(8),(SUBSTRING(@Password, 1, 8) ^ @ipadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 9, 8) ^ @ipadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 17, 8) ^ @ipadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 25, 8) ^ @ipadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 33, 8) ^ @ipadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 41, 8) ^ @ipadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 49, 8) ^ @ipadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 57, 8) ^ @ipadRFC2104))

    -- Loop unrolled for definite performance benefit
    -- Must XOR BLOCKSIZE bytes
    SET @k_opadRFC2104 = CONVERT(BINARY(8),(SUBSTRING(@Password, 1, 8) ^ @opadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 9, 8) ^ @opadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 17, 8) ^ @opadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 25, 8) ^ @opadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 33, 8) ^ @opadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 41, 8) ^ @opadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 49, 8) ^ @opadRFC2104))
      + CONVERT(BINARY(8),(SUBSTRING(@Password, 57, 8) ^ @opadRFC2104))

    SET @ThisIterationResult = HASHBYTES('SHA1', @k_opadRFC2104 + HASHBYTES('SHA1', @k_ipadRFC2104 + @FirstIterationDefinedResult))
    -- END   INLINED HMAC-SHA-512 for performance improvement

    SET @Working = @ThisIterationResult

    SET @CurrentIteration = 1
    WHILE @CurrentIteration < @IterationCount
    BEGIN
      --SET @ThisIterationResult = YourDB.dbo.Yourfn_CRYPT_HMAC_SHA1(@Password,@ThisIterationResult)

      -- NOTE: Inlining HMAC-SHA-512 appears to improve performance by a factor of six or so.  Setting the HMAC as an Inlined Table Valued Function instead of a Scalar function would reduce this disparity, of course.
      -- START INLINED HMAC-SHA-512 for performance improvement
      -- B = BLOCKSIZE (64 bytes for MD5, SHA1, SHA-256, and 128 bytes for SHA-384 and SHA-512, per RFC2104 and RFC4868)

      -- We've already hashed the password if we needed to!
      -- We've already generated @k_ipadRFC2104 and @k_opadRFC2104 both!

      SET @ThisIterationResult =  HASHBYTES('SHA1', @k_opadRFC2104 + HASHBYTES('SHA1', @k_ipadRFC2104 + @ThisIterationResult))
      -- END   INLINED HMAC-SHA-512 for performance improvement

      -- Loop unrolled for possible performance benefit
      -- Stupid conversion required because SQL Server can't do binary operations on two binary variables!!!
      -- Must XOR digest size bytes
      SET @Working = CONVERT(BINARY(8),(CONVERT(BIGINT,(SUBSTRING(@ThisIterationResult,1,8)))^SUBSTRING(@Working,1,8)))
        + CONVERT(BINARY(8),(CONVERT(BIGINT,(SUBSTRING(@ThisIterationResult,9,8)))^SUBSTRING(@Working,9,8)))
        + CONVERT(BINARY(4),(CONVERT(BIGINT,(SUBSTRING(@ThisIterationResult,17,4)))^SUBSTRING(@Working,17,4)))

      SET @CurrentIteration = @CurrentIteration + 1
    END -- WHILE @CurrentIteration rounds

    SELECT @output = @output +
      CASE
        WHEN @CurrentDigestSizeChunk = @NumDigestSizesRequiredToEncompassOutputbytes THEN CONVERT(BINARY(20),LEFT(@Working,@RemainderOutputbytesAfterNumDigestSizesMinusOne)) -- digest size in bytes
        ELSE CONVERT(BINARY(20),@Working) -- digest size in bytes
        END 
    SET @CurrentDigestSizeChunk = @CurrentDigestSizeChunk + 1
  END

  RETURN @output

END


GO
