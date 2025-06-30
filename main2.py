#----------IMPORTING THE NECESSARY MODULES------------

import streamlit as st #for web ui
import io #for file download and uplolad
import numpy as np #image to array conversion
import pickle #for encryption
import hashlib #for securing the password for converting text to crypto text
import matplotlib.pyplot as plt #for plotting the graph like histogram and pixel correlation
import random
from PIL import Image #for image opening and saving
from Crypto.Cipher import AES #for AES encryption
from Crypto.Util.Padding import pad, unpad #for AES padding and unpadding the bytes


#-------------ARNOLD'S CAT MAP SCRAMBLING-------------

#---shuffle the pixel of the image during encryption and add confusion that makes structure unrecognizable----
def arnold_scramble(image, rounds=1):
    img=image.copy()
    h,w,c=img.shape
    N=min(h, w)
    for _ in range(rounds):
        temp=img.copy()
        for x in range(N):
            for y in range(N):
                new_x=(x+y)%N
                new_y=(x+2*y)%N
                img[new_x, new_y]=temp[x, y]
    return img

#------------ARNOLD'S CAT MAP UNSCRAMBLING------------ 

#---shuffle the image back to original form by reshuffling the pixel to original form-----
def arnold_unscramble(image, rounds=1):
    img=image.copy()
    h,w,c=img.shape
    N=min(h, w)
    for _ in range(rounds):
        temp=img.copy()
        for x in range(N):
            for y in range(N):
                new_x=(2*x-y)%N
                new_y=(-x+y)%N
                img[new_x, new_y]=temp[x, y]
    return img

#-----------AES-ADVANCE ENCRYPTION STANDARD-----------

#---generation of password that is entered as text----
def password_to_aes_key(password):
    return hashlib.sha256(password.encode()).digest()[:16]


#--------------------AES ENCRYPTION-------------------

#---the image is firest faltten to an array and then add padding to the data----
#---AES ECB is used so that each 16bit block is independently using AES----
#---C=E(P)----
def encrypt_image(image_array, key):
    flat_bytes=image_array.flatten().tobytes()
    padded_data=pad(flat_bytes, AES.block_size)
    cipher=AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(padded_data)

#--------------------AES DECRYPTION-------------------

#---decryption is the reversal of the encryption of encryption----
#---length of encrypted bytes must be multiple of 16 as AES only works on 16 bits----
#---len(enc)%16=0----
#---P=D(C)----
def decrypt_image(encrypted_bytes, key, original_shape):
    if len(encrypted_bytes) % AES.block_size!=0:
        raise ValueError("Encrypted data length invalid for AES.")
    cipher=AES.new(key, AES.MODE_ECB)
    decrypted_data=cipher.decrypt(encrypted_bytes)
    unpadded=unpad(decrypted_data, AES.block_size)
    return np.frombuffer(unpadded, dtype=np.uint8).reshape(original_shape)

#---------------VIEW AND SAVE IMAGE FILE---------------

#---using the pickle module for the same----
def save_encrypted_data(encrypted_bytes, shape):
    return pickle.dumps({"data": encrypted_bytes, "shape": shape})
def load_encrypted_data(uploaded_file):
    return pickle.load(uploaded_file)

#------------HISTOGRAM ANALYSIS OF THE IMAGE-----------

#---shows how each intensity occur in the image and it is important to evaluate property of the images----
#---Histogram is made via distribution of the pixel in the image which shows the frequency of the image----
def plot_image_histogram(img_array, title="RGB HISTOGRAM ANALYSIS"):
    fig,ax=plt.subplots()
    colors=['r','g','b']
    for i, color in enumerate(colors):
        hist=np.histogram(img_array[:,:,i], bins=256, range=(0,256))[0]
        ax.plot(hist, color=color, label=f'{color.upper()} Channel')
    ax.set_title(title)
    ax.set_xlabel("PIXEL")
    ax.set_ylabel("FREQUENCY")
    ax.legend()
    st.pyplot(fig)

#---------------PIXEL CORRELATION GRAPH-----------------

#---shows the correlation between adjacent pixel i.e. i and i+1----
#---pixel of cipher text image must be zero to resist any kind of attack by the attacker----
def plot_pixel_correlation(img_array, title="PIXEL CORRELATION GRAPH"):
    fig,ax=plt.subplots()
    channel=img_array[:,:,0].flatten()
    sample_size=min(1000, len(channel)-1)
    indices=random.sample(range(len(channel)-1), sample_size)
    x_vals=channel[indices]
    y_vals=channel[[i+1 for i in indices]]
    ax.scatter(x_vals, y_vals, s=1, alpha=0.5, color='blue')
    ax.set_title(title)
    ax.set_xlabel("Pixel(i)")
    ax.set_ylabel("Pixel(i+1)")
    ax.grid(True)
    st.pyplot(fig)

#------------STREAMLIT WEB UI DEVELOPMENT-----------------

#---dividing the page into two tabs i.e. Encrypt and Decrypt----
st.set_page_config(page_title="AES combined with CHAOTIC MAP", layout="centered")
st.title("IMAGE ENCRYPTION BY AES COMBINED WITH CHAOTIC MAP")
ROUNDS=10
tab_encrypt, tab_decrypt = st.tabs(["ENCRYPT", "DECRYPT"])

#------------------------ENCRYPT TAB----------------------

#---image can be uploaded via system or clicked through the camera---
#---camera permissions must be granted from the browser----
#---once encrypted we can view the original image i.e. uploaded and its histogram and pixel xorrelation graph----
#---the encrypted image can be downloaded via .bin file which contains all teh data regarding the image----
with tab_encrypt:
    st.subheader("UPLOAD OR CAPTURE IMAGE")
    method=st.radio("IMAGE SOURCE", ["UPLOAD", "CAPTURE"])
    image=None

    if method=="UPLOAD":
        uploaded_file=st.file_uploader("UPLOAD IMAGE", type=["jpg", "jpeg", "png"])
        if uploaded_file:
            image=Image.open(uploaded_file).convert("RGB")
    else:
        cam_input=st.camera_input("CAPTURE")
        if cam_input:
            image=Image.open(cam_input).convert("RGB")
    password=st.text_input("ENTER PASSWORD", type="password", key="encrypt_password")
    if image and password:
        img_array=np.array(image)
        st.image(img_array, caption="ORIGINAL IMAGE", use_column_width=True)
        if st.button("HISTOGRAM FOR ORIGINAL IMAGE"):
            plot_image_histogram(img_array, "HISTOGRAM FOR ORIGINAL IMAGE")
        if st.button("PIXEL CORRELATION FOR ORIGINAL IMAGE"):
            plot_pixel_correlation(img_array, "PIXEL CORRELATION FOR ORIGINAL IMAGE")
        if st.button("ENCRYPT IMAGE"):
            scrambled=arnold_scramble(img_array, ROUNDS)
            key=password_to_aes_key(password)
            encrypted_bytes=encrypt_image(scrambled, key)
            st.session_state['encrypted_bytes']=encrypted_bytes
            st.session_state['original_shape']=img_array.shape
            st.success("ENCRYPTION SUCCESSFULL")
            try:
                h,w,c=img_array.shape
                reshaped_len=(len(encrypted_bytes)//(w*c))*w*c
                reshaped=np.frombuffer(encrypted_bytes[:reshaped_len],dtype=np.uint8)
                encrypted_preview = reshaped.reshape((-1,w,c))
                st.image(encrypted_preview.astype(np.uint8), caption="Encrypted Image Preview",use_column_width=True)
                st.session_state['encrypted_preview']=encrypted_preview
            except:
                st.warning("ERROR")
            encrypted_bin=save_encrypted_data(encrypted_bytes, img_array.shape)
            st.download_button("DOWNLOAD ENCRYPTED FILE", data=encrypted_bin, file_name="encrypted_image.bin",mime="application/octet-stream")
        if st.session_state.get("encrypted_preview") is not None:
            if st.button("HISTOGRAM FOR ENCRYPTED IMAGE"):
                plot_image_histogram(st.session_state['encrypted_preview'].astype(np.uint8),"HISTOGRAM FOR ENCRYPTED IMAGE")
            if st.button("PIXEL CORRELATION FOR ENCRYPTED IMAGE"):
                plot_pixel_correlation(st.session_state['encrypted_preview'].astype(np.uint8),"PIXEL CORRELATION FOR ENCRYPTED IMAGE")

#------------------------DECRYPT TAB----------------------

#---the .bin file is uploaded and password is entered, if the password matches the image is decrypted----
#---we can download the decrypted image as .png because .png has lossless conversion property----
with tab_decrypt:
    encrypted_file=st.file_uploader("UPLOAD .bin FILE", type=["bin"])
    dec_password=st.text_input("ENTER PASSWORD", type="password", key="decrypt_password")
    if encrypted_file and dec_password:
        if st.button("DECRYPT IMAGE"):
            try:
                content=load_encrypted_data(encrypted_file)
                key=password_to_aes_key(dec_password)
                decrypted_array=decrypt_image(content["data"], key, content["shape"])
                final_image=arnold_unscramble(decrypted_array, ROUNDS)
                st.session_state['decrypted_image']=final_image
                st.image(final_image, caption="DECRYPTED IMAGE", use_column_width=True)
                buf=io.BytesIO()
                Image.fromarray(final_image).save(buf, format='PNG')
                st.download_button("DOWNLOAD DECRYPTED IMAGE", data=buf.getvalue(),file_name="decrypted_image.png",mime="image/png")
            except Exception as e:
                st.error(f"FAILED: {e}")
        if st.session_state.get("decrypted_image") is not None:
            if st.button("HISTOGRAM FOR DECRYPTED IMAGE"):
                plot_image_histogram(st.session_state['decrypted_image'].astype(np.uint8),"HISTOGRAM FOR DECRYPTED IMAGE")
            if st.button("PIXEL CORRELATION FOR DECRYPTED IMAGE"):
                plot_pixel_correlation(st.session_state['decrypted_image'].astype(np.uint8),"PIXEL CORRELATION FOR DECRYPTED IMAGE")

#----------------------------------------------------------------------------------------------------------------E.......N.......D---------------------------------------------------------------------------------------------------------#
