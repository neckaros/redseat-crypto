All in one stream encoding

No need to understand crypto: Wrap your *Reader* / *Writer* width one of *AesReader* / *AesWriter* and read/write!

*All you need to create a Reader is* 
* a key That you can create thanks to 
    - A SALT (random bytes per application so you can create your own (it has to be 128Bits) or if you want to decode RedSeat files use our own below)
    - A String key
    ```rust
    const SALT: &str = "e5709660b22ab0803630cb963f703b83";
    let salt = URL_SAFE.decode(SALT).unwrap();
    let key = derive_key("test password", &salt);
    ```

*All you need to create a writer is*
* an (IV): You can generate one thanks to the ```random_iv(None)``` function
* as key like for the writer

RedSeat Crypto is used by the RedSeat app (for encrypted backup and encrypted libraries) and add header that you can customize inside the crypted file:
```rust
pub struct CryptoInfo{
    pub thumb: Option<Vec<u8>>,
    pub mime: Option<String>,
    pub thumb_mime: Option<String>,
    pub info: Option<String>,
}
```
All field are optional but it allows you to store in the crypted file thumb data and any info in String format (for example serialized JSON).

Therefore just by reading the header you can extract the thumb or info without reading the full file:
* Read the first of the file it will contains bytes:
    - 16 to get the IV (use as input for decryption with the Key)
    - 4 to store encrypted thumb size = T (can be 0) (u32 BigEndian: ```u32::from_be_bytes()```)
    - 4 to store encrypted Info size = I (can be 0) (u32 BigEndian: ```u32::from_be_bytes()```)
    - 32 to store thumb mimetype (string UTF8 ```String::from_utf8()```)
    - 256 to store file mimetype (string UTF8 ```String::from_utf8()```)

For exemple if T (thumb size) is 240: Thumb will be at byptes [313 to 553]

Next versions will provide easy functionality to retreive Thumb and Info

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

See the tests for more examples

Encryption used: AES256 with CBC Block Mode