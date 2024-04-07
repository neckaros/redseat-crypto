


use std::io::{Read, Write, Seek, SeekFrom, Result, Error, ErrorKind};

use crypto::hmac::Hmac;
use crypto::pbkdf2;
use crypto::sha1::Sha1;
use crypto::symmetriccipher::{BlockDecryptor, BlockEncryptor, Encryptor, Decryptor};
use crypto::blockmodes::{PkcsPadding, CbcEncryptor, CbcDecryptor, EncPadding, DecPadding};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult, WriteBuffer, ReadBuffer};
use rand::rngs::OsRng;
use rand::RngCore;
#[cfg(feature="serde")]
use serde::{Deserialize, Serialize};

pub use crypto::aessafe;


const KEY_SIZE: usize = 32;
const BUFFER_SIZE: usize = 8192;


/// Added as header in the encrypted file (just after the IV)
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq)]
pub struct CryptoInfo{
    pub thumb: Option<Vec<u8>>,
    pub mime: Option<String>,
    pub thumb_mime: Option<String>,
    pub info: Option<String>,
}

impl CryptoInfo {
    pub fn encrypted_thumb_size(&self) -> u32 {
        self.thumb.as_ref().and_then(|s| Some(get_encrypted_size(s.len() as u64))).unwrap_or(0) as u32
    }

    pub fn encrypted_info_size(&self) -> u32 {
        self.info.as_ref().and_then(|s| Some(get_encrypted_size(s.as_bytes().len() as u64))).unwrap_or(0) as u32
    }

    pub fn size(&self) -> u64 {
        self.encrypted_thumb_size() as u64 + self.encrypted_info_size() as u64
    } 

    pub fn full_size(&self) -> u64 {
        Self::header_size() + self.size()
    } 

    pub fn full_size_with_iv(&self) -> u64 {
        Self::header_size() + 16 + self.size()
    } 

    pub fn header_size() -> u64 {
        4 + 4 + 32 + 256
    }

    pub fn mime_as_bytes(&self) -> Vec<u8>{
        format!("{:width$}", self.mime.clone().unwrap_or("".to_owned()), width=256).as_bytes().to_vec()
    }

    pub fn thumb_mime_as_bytes(&self) -> Vec<u8>{
        format!("{:width$}", self.thumb_mime.clone().unwrap_or("".to_owned()), width=32).as_bytes().to_vec()
    }

    
    pub fn write<E: BlockEncryptor, W: Write>(&self, writer: &mut AesWriter<E, W>, iv: &Vec<u8>) -> Result<usize> {
        //4 to store encrypted thumb size = T (can be 0)
        //4 to store encrypted Info size = I (can be 0)
        //32 to store thumb mimetype
        //256 to store file mimetype
        //T Bytes for the encrypted thumb
        //I Bytes for the encrypted info
        let mut writen = 0;
        writen += writer.write_direct(&self.encrypted_thumb_size().to_be_bytes())?;
        writen += writer.write_direct(&self.encrypted_info_size().to_be_bytes())?;

        writen += writer.write_direct(&self.thumb_mime_as_bytes())?;
        writen += writer.write_direct(&self.mime_as_bytes())?;

        if let Some(thumb) = &self.thumb {
            let mut read_buffer = RefReadBuffer::new(thumb);
            let mut out = [0; 16];
            let mut write_buffer = RefWriteBuffer::new(&mut out);
            
            loop {
                let result = writer.enc.encrypt(&mut read_buffer, &mut write_buffer, true) .map_err(|e| Error::new(ErrorKind::Other, format!("thumb encryption error: {:?}", e)))?;
                let mut data = &write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter().map(|i| i.clone()).collect::<Vec<u8>>();
                
                writer.write_direct(&mut data)?;
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }           
            writer.enc.reset(&iv)
        }
        if let Some(info) = &self.info {
            let mut read_buffer = RefReadBuffer::new(info.as_bytes());
            let mut out = [0; 16];
            let mut write_buffer = RefWriteBuffer::new(&mut out);
            
            loop {
                let result = writer.enc.encrypt(&mut read_buffer, &mut write_buffer, true) .map_err(|e| Error::new(ErrorKind::Other, format!("thumb encryption error: {:?}", e)))?;
                let mut data = &write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter().map(|i| i.clone()).collect::<Vec<u8>>();
                
                writer.write_direct(&mut data)?;
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }           
            writer.enc.reset(&iv)
        }

        Ok(writen) 
    }

    pub fn from_reader<D: BlockDecryptor, R: Read>(reader: &mut AesReader<D, R>, iv: &Vec<u8>) -> Result<CryptoInfo> {
        //4 to store encrypted thumb size = T (can be 0)
        //4 to store encrypted Info size = I (can be 0)
        //32 to store thumb mimetype
        //256 to store file mimetype
        //T Bytes for the encrypted thumb
        //I Bytes for the encrypted info
        let mut buf = vec![0u8; 4];
        reader.read_exact_raw(&mut buf)?;
        let size_thumb = u32::from_be_bytes(buf[0..4].try_into().map_err(|_| std::io::ErrorKind::Other)?);

        let mut buf = vec![0u8; 4];
        reader.read_exact_raw(&mut buf)?;
        let size_info = u32::from_be_bytes(buf[0..4].try_into().map_err(|_| std::io::ErrorKind::Other)?);


        let mut buf = vec![0u8; 32];
        reader.read_exact_raw(&mut buf)?;
        let thumb_mime = String::from_utf8(buf).map_err(|_| std::io::ErrorKind::Other)?.trim_end().to_string();

        let mut buf = vec![0u8; 256];
        reader.read_exact_raw(&mut buf)?;
        let file_mime = String::from_utf8(buf).map_err(|_| std::io::ErrorKind::Other)?.trim_end().to_string();


        let thumb = if size_thumb == 0 {
            None
        } else {
            let mut crypt_buf = vec![0u8; size_thumb as usize];
            reader.read_exact_raw(&mut crypt_buf)?;
            let mut read_buffer = RefReadBuffer::new(&crypt_buf);
            let mut buffer = [0; 16];
            let mut write_buffer = RefWriteBuffer::new(&mut buffer);
            let mut decryted_thumb: Vec<u8> = vec![];
            reader.dec.reset(&iv);
            loop {
                let result = reader.dec.decrypt(&mut read_buffer, &mut write_buffer, true) .map_err(|e| Error::new(ErrorKind::Other, format!("thumb decryption error: {:?}", e)))?;

                decryted_thumb.append(
                    &mut write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .map(|&i| i.clone()).collect::<Vec<u8>>(),
                );
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }
            reader.dec.reset(&iv);
            Some(decryted_thumb)
        };

        let info = if size_info == 0 {
            None
        } else {
            let mut crypt_buf = vec![0u8; size_info as usize];
            reader.read_exact_raw(&mut crypt_buf)?;
            let mut read_buffer = RefReadBuffer::new(&crypt_buf);
            let mut buffer = [0; 16];
            let mut write_buffer = RefWriteBuffer::new(&mut buffer);
            let mut decrypted_info: Vec<u8> = vec![];
            loop {
                let result = reader.dec.decrypt(&mut read_buffer, &mut write_buffer, true) .map_err(|e| Error::new(ErrorKind::Other, format!("info decryption error: {:?}", e)))?;

                decrypted_info.append(
                    &mut write_buffer
                        .take_read_buffer()
                        .take_remaining()
                        .iter()
                        .map(|&i| i.clone()).collect::<Vec<u8>>(),
                );
                match result {
                    BufferResult::BufferUnderflow => break,
                    BufferResult::BufferOverflow => {}
                }
            }
            reader.dec.reset(&iv);
            Some(String::from_utf8(decrypted_info).unwrap_or("".to_owned()))
        };
        



        Ok(CryptoInfo {
            thumb,
            mime: if file_mime == "" {
                None
            } else {
                Some(file_mime)
            },
            thumb_mime: if thumb_mime == "" {
                None
            } else {
                Some(thumb_mime)
            },
            info,
        })
    }

}


pub fn get_encrypted_size(size: u64) -> u64 {
    size + (16 - size % 16)
} 


pub fn random_iv(block_size: Option<usize>) -> Vec<u8> {
    let mut iv = vec![0u8; block_size.unwrap_or(16)];
    OsRng.fill_bytes(&mut iv);
    iv
} 

pub fn random_iv_for_encryptor<E: BlockEncryptor>(enc: E) -> Vec<u8> {
    let mut iv = vec![0u8; enc.block_size()];
    OsRng.fill_bytes(&mut iv);
    iv
} 

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut dk = [0u8; KEY_SIZE]; // derived key
    let mut mac = Hmac::new(Sha1::new(), password.as_bytes());
    pbkdf2::pbkdf2(&mut mac, salt, 1000, &mut dk);
    dk
}

pub struct AesWriter<E: BlockEncryptor, W: Write> {
    /// Writer to write encrypted data to
    writer: Option<W>,
    /// Encryptor to encrypt data with
    pub enc: CbcEncryptor<E, EncPadding<PkcsPadding>>,
    /// Indicates weather the encryptor has done its final operation (inserting padding)
    closed: bool,
}

impl<E: BlockEncryptor, W: Write> AesWriter<E, W> {
    //! If you don't want the header you can use this initializer
    pub fn new(iv: Vec<u8>, mut writer: W, enc: E) -> Result<AesWriter<E, W>> {
        writer.write_all(&iv)?;
        Ok(AesWriter {
            writer: Some(writer),
            enc: CbcEncryptor::new(enc, PkcsPadding, iv),
            closed: false,
        })
    }

    /// Initializer that will store info in the file. You muse use the AesReader::new_with_info to decrypt this kind of file
    pub fn new_with_infos(iv: Vec<u8>, infos: CryptoInfo, mut writer: W, enc: E) -> Result<AesWriter<E, W>> {
        writer.write_all(&iv)?;
        
        let mut aes_writer = AesWriter {
            writer: Some(writer),
            enc: CbcEncryptor::new(enc, PkcsPadding, iv.clone()),
            closed: false,
        };

        infos.write(&mut aes_writer, &iv)?;


        Ok(aes_writer)
    }

    /// Encrypts passed buffer and writes all resulting encrypted blocks to the underlying writer
    ///
    /// # Parameters
    ///
    /// * **buf**: Plaintext to encrypt and write
    /// * **eof**: If the provided buf is the last one to come and therefore encryption should be
    ///     finished and padding added.
    fn encrypt_write(&mut self, buf: &[u8], eof: bool) -> Result<usize> {
        let mut read_buf = RefReadBuffer::new(buf);
        let mut out = [0u8; BUFFER_SIZE];
        let mut write_buf = RefWriteBuffer::new(&mut out);
        loop {
            let res = self.enc.encrypt(&mut read_buf, &mut write_buf, eof)
                .map_err(|e| Error::new(ErrorKind::Other, format!("encryption error: {:?}", e)))?;
            let mut enc = write_buf.take_read_buffer();
            let enc = enc.take_remaining();
            self.writer.as_mut().unwrap().write_all(enc)?;
            match res {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow if eof =>
                    panic!("read_buf underflow during encryption with eof"),
                BufferResult::BufferOverflow => {},
            }
        }
        // CbcEncryptor has its own internal buffer and always consumes all input
        assert_eq!(read_buf.remaining(), 0);
        Ok(buf.len())
    }

    pub fn write_direct(&mut self, buf: &[u8]) -> Result<usize> {
        let written = self.writer.as_mut().unwrap().write(buf)?;
        Ok(written)
    }
}

impl<E: BlockEncryptor, W: Write> Write for AesWriter<E, W> {
    /// Encrypts the passed buffer and writes the result to the underlying writer.
    ///
    /// Due to the blocksize of CBC not all data will be written instantaneously.
    /// For example if 17 bytes are passed, the first 16 will be encrypted as one block and written
    /// the underlying writer, but the last byte won't be encrypted and written yet.
    ///
    /// If [`flush`](#method.flush) has been called, this method will always return an error.
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if self.closed {
            return Err(Error::new(ErrorKind::Other, "AesWriter is closed"));
        }
        let written = self.encrypt_write(buf, false)?;
        Ok(written)
    }

    /// Flush this output stream, ensuring that all intermediately buffered contents reach their destination.
    /// [Read more](https://doc.rust-lang.org/nightly/|_| std/io/trait.Write.html#tymethod.flush)
    ///
    /// **Warning**: When this method is called, the encryption will finish and insert final padding.
    /// After calling `flush`, this writer cannot be written to anymore and will always return an
    /// error.
    fn flush(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.encrypt_write(&[], true)?;
        self.closed = true;
        self.writer.as_mut().unwrap().flush()
    }
}

impl<E: BlockEncryptor, W: Write> Drop for AesWriter<E, W> {
    /// Drops this AesWriter trying to finish encryption and to write everything to the underlying writer.
    fn drop(&mut self) {
        if self.writer.is_some() {
            if !std::thread::panicking() {
                self.flush().unwrap();
            } else {
                let _ = self.flush();
            }
        }
    }
}

pub struct AesReader<D: BlockDecryptor, R: Read> {
    /// Reader to read encrypted data from
    reader: R,
    /// Decryptor to decrypt data with
    pub dec: CbcDecryptor<D, DecPadding<PkcsPadding>>,
    /// Block size of BlockDecryptor, needed when seeking to correctly seek to the nearest block
    block_size: usize,
    /// Buffer used to store blob needed to find out if we reached eof
    buffer: Vec<u8>,
    /// Indicates wheather eof of the underlying buffer was reached
    eof: bool,
}

impl<D: BlockDecryptor, R: Read> AesReader<D, R> {
    /// Creates a new AesReader.
    ///
    /// Assumes that the first block of given reader is the IV.
    ///
    /// # Parameters
    ///
    /// * **reader**: Reader to read encrypted data from
    /// * **dec**: [`BlockDecryptor`][bd] to use for decyrption
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate crypto;
    /// # extern crate rand;
    /// # extern crate aesstream;
    /// # use crypto::aessafe::AesSafe128Decryptor;
    /// # use rand::{OsRng, Rng};
    /// # use |_| std::io::Result;
    /// # use |_| std::fs::File;
    /// # use aesstream::AesReader;
    /// # fn foo() -> Result<()> {
    /// let key: [u8; 16] = OsRng::new()?.gen();
    /// let decryptor = AesSafe128Decryptor::new(&key);
    /// let file = File::open("...")?;
    /// let mut reader = AesReader::new(file, decryptor)?;
    /// # Ok(())
    /// # }
    /// # fn main() { let _ = foo(); }
    /// ```
    ///
    /// [bd]: https://docs.rs/rust-crypto/0.2.36/crypto/symmetriccipher/trait.BlockDecryptor.html
    pub fn new(mut reader: R, dec: D) -> Result<AesReader<D, R>> {
        let mut iv = vec![0u8; dec.block_size()];
        reader.read_exact(&mut iv)?;
        Ok(AesReader {
            reader: reader,
            block_size: dec.block_size(),
            dec: CbcDecryptor::new(dec, PkcsPadding, iv),
            buffer: Vec::new(),
            eof: false,
        })
    }

    /// Will give you the decrypted infos and a Reader with decrypted data
    pub fn new_with_infos(mut reader: R, dec: D) -> Result<(CryptoInfo, AesReader<D, R>)> {
        let mut iv = vec![0u8; dec.block_size()];
        reader.read_exact(&mut iv)?;
        
        let mut aes_reader = AesReader {
            reader,
            block_size: dec.block_size(),
            dec: CbcDecryptor::new(dec, PkcsPadding, iv.clone()),
            buffer: Vec::new(),
            eof: false,
        };

        let infos = CryptoInfo::from_reader(&mut aes_reader, &iv)?;

        Ok((infos, aes_reader))
    }

    /// Reads at max BUFFER_SIZE bytes, handles potential eof and returns the buffer as Vec<u8>
    fn fill_buf(&mut self) -> Result<Vec<u8>> {
        let mut eof_buffer = vec![0u8; BUFFER_SIZE];
        let read = self.reader.read(&mut eof_buffer)?;
        self.eof = read == 0;
        eof_buffer.truncate(read);
        Ok(eof_buffer)
    }

    /// Reads and decrypts data from the underlying stream and writes it into the passed buffer.
    ///
    /// The CbcDecryptor has an internal output buffer, but not an input buffer.
    /// Therefore, we need to take care of letfover input.
    /// Additionally, we need to handle eof correctly, as CbcDecryptor needs to correctly interpret
    /// padding.
    /// Thus, we need to read 2 buffers. The first one is read as input for decryption and the second
    /// one to determine if eof is reached.
    /// The next time this function is called, the second buffer is passed as input into decryption
    /// and the first buffer is filled to find out if we reached eof.
    ///
    /// # Parameters
    ///
    /// * **buf**: Buffer to write decrypted data into.
    fn read_decrypt(&mut self, buf: &mut [u8]) -> Result<usize> {
        // if this is the first iteration, fill internal buffer
        if self.buffer.is_empty() && !self.eof {
            self.buffer = self.fill_buf()?;
        }

        let buf_len = buf.len();
        let mut write_buf = RefWriteBuffer::new(buf);
        let res;
        let remaining;
        {
            let mut read_buf = RefReadBuffer::new(&self.buffer);

            // test if CbcDecryptor still has enough decrypted data or we have enough buffered
            res = self.dec.decrypt(&mut read_buf, &mut write_buf, self.eof)
                .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
            remaining = read_buf.remaining();
        }
        // keep remaining bytes
        let len = self.buffer.len();
        self.buffer.drain(..(len - remaining));
        // if we were able to decrypt, return early
        match res {
            BufferResult::BufferOverflow => return Ok(buf_len),
            BufferResult::BufferUnderflow if self.eof => return Ok(write_buf.position()),
            _ => {}
        }

        // else read new buffer
        let mut dec_len = 0;
        // We must return something, if we have something.
        // If the reader doesn't return enough so that we can decrypt a block, we need to continue
        // reading until we have enough data to return one decrypted block, or until we reach eof.
        // If we reach eof, we will be able to decrypt the final block because of padding.
        while dec_len == 0 && !self.eof {
            let eof_buffer = self.fill_buf()?;
            let remaining;
            {
                let mut read_buf = RefReadBuffer::new(&self.buffer);
                self.dec.decrypt(&mut read_buf, &mut write_buf, self.eof)
                    .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
                let mut dec = write_buf.take_read_buffer();
                let dec = dec.take_remaining();
                dec_len = dec.len();
                remaining = read_buf.remaining();
            }
            // keep remaining bytes
            let len = self.buffer.len();
            self.buffer.drain(..(len - remaining));
            // append newly read bytes
            self.buffer.extend(eof_buffer);
        }
        Ok(dec_len)
    }

    fn read_exact_raw(&mut self, mut buf: &mut [u8]) -> Result<()> {
        self.reader.read_exact(&mut buf)
    }

}
impl<D: BlockDecryptor, R: Read + Seek> AesReader<D, R> {
    /// Seeks to *offset* from the start of the file
    fn seek_from_start(&mut self, offset: u64) -> Result<u64> {
        let block_num = offset / self.block_size as u64;
        let block_offset = offset % self.block_size as u64;
        // reset CbcDecryptor
        self.reader.seek(SeekFrom::Start((block_num - 1) * self.block_size as u64))?;
        let mut iv = vec![0u8; self.block_size];
        self.reader.read_exact(&mut iv)?;
        self.dec.reset(&iv);
        self.buffer = Vec::new();
        self.eof = false;
        let mut skip = vec![0u8; block_offset as usize];
        self.read_exact(&mut skip)?;
        // subtract IV
        Ok(offset - 16)
    }
}

impl<D: BlockDecryptor, R: Read> Read for AesReader<D, R> {
    /// Reads encrypted data from the underlying reader, decrypts it and writes the result into the
    /// passed buffer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read = self.read_decrypt(buf)?;
        Ok(read)
    }
}

impl<D: BlockDecryptor, R: Read + Seek> Seek for AesReader<D, R> {
    /// Seek to an offset, in bytes, in a stream.
    /// [Read more](https://doc.rust-lang.org/nightly/|_| std/io/trait.Seek.html#tymethod.seek)
    ///
    /// When seeking, this reader takes care of reinitializing the CbcDecryptor with the correct IV.
    /// The passed position does *not* need to be aligned to the blocksize.
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match pos {
            SeekFrom::Start(offset) => {
                // +16 because first block is the iv
                self.seek_from_start(offset + 16)
            },
            SeekFrom::End(_) | SeekFrom::Current(_) => {
                let pos = self.reader.seek(pos)?;
                self.seek_from_start(pos)
            },
        }
    }
}



#[cfg(test)]
mod tests {
    use std::{fs::{remove_file, File}, io::copy, path::PathBuf, str::FromStr};

    use crypto::aessafe::{AesSafe256Decryptor, AesSafe256Encryptor};
    use base64::{engine::general_purpose::URL_SAFE, Engine as _};
    use super::*;
  

    const SALT: &str = "e5709660b22ab0803630cb963f703b83";


    #[test]
    fn encrypted_size() {
        let r = get_encrypted_size(8);
        assert_eq!(r, 16);

        let r = get_encrypted_size(29);
        assert_eq!(r, 32);
    }


    #[test]
    fn encrypted_info() {
        let info = CryptoInfo {
            thumb: Some(random_iv(Some(145))),
            mime: Some("video/quicktime-mov".to_owned()),
            thumb_mime: Some("image/jpeg".to_owned()),
            info: Some("{JSONEXEMPLE====}".to_owned()),
        };

        assert_eq!(info.mime_as_bytes().len(), 256, "Mime must be 256 bytes");
        assert_eq!(info.thumb_mime_as_bytes().len(), 32, "Thumb Mime must be 32 bytes");


        let expected = 4 + 4 + 32 + 256 + 160 + 32;
        assert_eq!(info.full_size(), expected);

        let expected = 16 + 4 + 4 + 32 + 256 + 160 + 32;
        assert_eq!(info.full_size_with_iv(), expected);

        let expected = 160 + 32;
        assert_eq!(info.size(), expected);

    }

    #[test]
    fn encrypt() -> Result<()> {
        let test_path = PathBuf::from_str("test_data/test").unwrap();
        if test_path.exists() {
            remove_file(&test_path)?;
        }

        let salt = URL_SAFE.decode(SALT).unwrap();
        let key = derive_key("test password", &salt);
        let iv = random_iv(None);

        {
            let writer = File::create(&test_path)?;
            let encryptor = AesSafe256Encryptor::new(&key);
            let mut aes_writer = AesWriter::new(iv, writer, encryptor)?;
            aes_writer.encrypt_write("test encrypted".as_bytes(), true)?;
        }
        {
            let reader = File::open(&test_path)?;
            let decryptor = AesSafe256Decryptor::new(&key);
    
            let mut aes_reader = AesReader::new(reader, decryptor)?;
            let mut decrypted = String::new();
            aes_reader.read_to_string(&mut decrypted)?;

            assert_eq!(decrypted, "test encrypted", "Decrypted different than encprypted");
        }
        Ok(())
    }


    #[test]
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

/* 
    #[test]
    fn decrypt_file() -> Result<()> {
        let test_path = PathBuf::from_str("test_data/file").unwrap();
    
        let reader = File::open(&test_path)?;
        let salt = URL_SAFE.decode(SALT).unwrap();
        let key = derive_key("XXXXXX", &salt);

        let decryptor = AesSafe256Decryptor::new(&key);

        let (dec_infos ,mut aes_reader) = AesReader::new_with_infos(reader, decryptor)?;
        println!("INfos: {:?}", dec_infos);
        
        let output_path = PathBuf::from_str("test_data/file.heic").unwrap();
        if output_path.exists() {
            remove_file(&output_path)?;
        }
        let mut writer = File::create(output_path)?;

        copy(&mut aes_reader, &mut writer)?;
    
        Ok(())
    }
    */
}