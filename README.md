AES combined with Chaos Map

Description
This is an Online Image Encryptor that encrypts your image using AES - Advance Encryption Standards combined with Arnold's Cat Chaotic Map. 
It allows you to upload the image as well as capture it via your camera and encrypt it with a Password.
One can view the Histogram Analysis and the Pixel Correlation graph of all Original Image, Encrypted Image and Decrypted Image

This Encryptor is made using Python 3.10 and deployed via Streamlit.

Libraries required:
streamlit
io
numpy
pickle
hashlib
matplotlib
PIL
Crypto

AES-Advance Encryption Standards
ENCRYPTION
converting image in bytes of 16(if not) by adding of padding i.e. len%16==0
AES ECB is used so that each 16bit block is independently using AES
CIPHER=ENCRYPTION(PLAIN)

1. Add Round Key
2. SubBytes
3. Shift Rows
4. Mix Column

DECRYPTION
length of encrypted bytes must be multiple of 16
len(encr)%16==0
PLAIN=DECRYPTION(CIPHER)
padding must be removed to find the original bytes so that image can be retrieved

ARNOLD CAT MAP
used for shuffling the pixel before encryption that adds confusion and make structure of the image unrecognizable

SCRAMBLING
new_x=(x+y)mod N
new_y=(x+2y)mod N
UNSCRAMBLING
x=(2new_x-new_y)mod N
y=(-new_x+new_y)mod N
