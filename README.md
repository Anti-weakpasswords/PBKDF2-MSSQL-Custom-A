PBKDF2-MSSQL-Custom-A
=====================

Microsoft SQL Server PBKDF2 implementations.

Test vectors are included in the comments section at the beginning.

NOTE: Despite the inlining of HMAC code and other optimizations, SQL Server as a whole is absolutely terrible at doing this kind of math efficiently.  However, it is a very easily readable implementation, it does pass the test vectors, and it is useful when there isn't anything else or for extremely low volume use.
