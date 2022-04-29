# C/c++ Data Secured Chat Client

---Framework---

UI:
  Managed through the use of QT(Major Verion 6).

Sockets:
  Through the OpenSSL libraries.
  
AES:
  Relies on OpenSSL Crypto library.


---Modules---

Ciphers:
  Ceaser Cipher ascii 48 to 122 (0-Z-z)
  Substitutin Cipher(Must supply key of 52 in length)(upper and lowercase)
  String reversal
  
Encryptors:
  AES(cbc mode, 16byte key)
  
File Sending:
  Both users must have folders selected for files to be transferred
  You may not request files that are not present in directory
  You may not send a file before a request for it was made
  
Chat:
  It's a chat
  Press end to send your message
  Will not process messages with no length
  
---In works---

SSL:
  Problems with dependencies. Cannot properly build on current system.
  
xor cipher:
  When the characters of same value are xor'd, it creates a null byte.
  Due to c-sockets relying on c-strings, it needs a better method of encoding, in order to send.
