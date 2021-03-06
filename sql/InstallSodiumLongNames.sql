CREATE FUNCTION sodium_box_publickey RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_box_publickey_from_secretkey RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_box_secretkey RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_kdf_derive_from_key RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_kx_publickey RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_kx_secretkey RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_pwhash_str RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_pwhash_str_needs_rehash RETURNS INTEGER SONAME 'sodium.so';
CREATE FUNCTION sodium_pwhash_str_verify RETURNS INTEGER SONAME 'sodium.so';
CREATE FUNCTION sodium_sign_publickey RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_sign_publickey_from_secretkey RETURNS STRING SONAME 'sodium.so';
CREATE FUNCTION sodium_sign_secretkey RETURNS STRING SONAME 'sodium.so';
