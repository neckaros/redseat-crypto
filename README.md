All in one stream encoding

No need to understand crypto: Wrap your *Reader* / *Writer* width one of *AesReader* / *AesWriter* and read/write!

RedSeat Crypto is used by the RedSeat app (for encrypted backup and encrypted libraries) and add header that you can customize inside the crypted file:
```rust
pub struct CryptoInfo{
    pub thumb: Option<Vec<u8>>,
    pub mime: Option<String>,
    pub thumb_mime: Option<String>,
    pub info: Option<String>,
}
```
All field are optional but it allows you to store in the crypted file thumb data and any info in String format (for example serialized JSON)


Exemple usage with information:

```rust
fn encrypt_with_infos() -> Result<()> {
        let infos = CryptoInfo {
            thumb: Some(random_iv(Some(145))),
            mime: Some("video/quicktime-mov".to_owned()),
            thumb_mime: Some("image/jpeg".to_owned()),
            info: Some("{JSONEXEMPLE====}".to_owned()),
        };


        let test_path = PathBuf::from_str("test_data/test_infos").unwrap();
        if test_path.exists() {
            remove_file(&test_path)?;
        }

        let salt = URL_SAFE.decode(SALT).unwrap();
        let key = derive_key("test password", &salt);
        let iv = random_iv(None);

        {
            let writer = File::create(&test_path)?;
            let encryptor = AesSafe256Encryptor::new(&key);
            let mut aes_writer = AesWriter::new_with_infos(iv, infos.clone(), writer, encryptor)?;
            aes_writer.encrypt_write("test encrypted".as_bytes(), true)?;
        }
        {
            let reader = File::open(&test_path)?;
            let decryptor = AesSafe256Decryptor::new(&key);
    
            let (dec_infos ,mut aes_reader) = AesReader::new_with_infos(reader, decryptor)?;
            let mut decrypted = String::new();
            assert_eq!(infos, dec_infos, "infos different than initial infos");
            aes_reader.read_to_string(&mut decrypted)?;
            assert_eq!(decrypted, "test encrypted", "Decrypted different than encprypted");
        }
        Ok(())
    }
```


Encryption used: AES256 with CBC Block Mode