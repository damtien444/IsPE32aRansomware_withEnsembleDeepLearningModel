import os
from PIL import Image

import streamlit as st
from predict import predict_single_file
from utils.preprocessing import createRGBImageWithSectionAndPEBest

tempfolder = r"E:\Malware Image Based\drive-download-20220515T075039Z-001\temp"

def save_uploadedfile(uploadedfile, tempfolder):
    with open(os.path.join(tempfolder, uploadedfile.name), "wb") as f:
        f.write(uploadedfile.getbuffer())
    return os.path.join(tempfolder, uploadedfile.name)

weight= r"result/exp/best.pt"
def show_predict_page():
    st.title("Is this executable a Ransomware?")

    st.write("### We need an Portable Executable 32bit file as the input of the prediction pipeline! ###")

    file = st.file_uploader(label="Upload file")

    ok = st.button("Predict!")

    if ok:
        tempfile = save_uploadedfile(file, tempfolder)
        try:
            saved = createRGBImageWithSectionAndPEBest(tempfile, withPe=True)
            image = Image.open(saved)
            st.image(image)
            pro, pre = predict_single_file(weight_dir=weight, image_path=saved, cuda=True)

            predict = "not ransomware"

            if pre == 1:
                predict = "ransomware"

            st.write(f"### The file is {predict} with probability {pro * 100}% ###")
        except:
            st.write("The input file is not PE32 or corrupted!")

