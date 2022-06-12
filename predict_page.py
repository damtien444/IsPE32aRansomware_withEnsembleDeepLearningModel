import os
from pathlib import Path

import pandas as pd
from PIL import Image

import streamlit as st
from predict import predict_single_file
from utils.Extract import extract_infos, columns
from utils.preprocessing import createRGBImageWithSectionAndPEBest

st.set_page_config(
     page_title="Is this file a ransomware?",
     layout="wide"
 )

weight_file_id = "1ybTh2BTrrH9fc48h5hsdU4PNhhJwf8sM"
weight_link = "https://drive.google.com/file/d/1ybTh2BTrrH9fc48h5hsdU4PNhhJwf8sM/view?usp=sharing"
tempfolder = os.getcwd() + os.sep + "temp"
weight_imcec_dir= r"result/exp/best.pt"



def save_uploadedfile(uploadedfile, tempfolder):
    with open(os.path.join(tempfolder, uploadedfile.name), "wb") as f:
        f.write(uploadedfile.getbuffer())
    return os.path.join(tempfolder, uploadedfile.name)


def show_predict_page():


    st.title("Is this executable a Ransomware?")

    st.write("To figure out the fact that a pe file is a ransomware is a pain process. In which experts "
             "have to do static and dynamic analysis. This tool is meant to help them to classify them easily.")

    st.write("This tools use a complex ensemble deeplearning model (Resnet50 and VGG16 base model) trained on a data set "
             "of 3000 samples including ransomware and other file.")

    st.write("""The main contributions to this study include:\n
1.   Classification of ransomware uses images containing information from PE headers, thereby helping to increase the similarity between samples of the same variant strain.\n
2.   Select features from PE headers using machine learning models and encode them into images representing ransomware samples.\n
3.   Building a combination model from famous CNN networks such as ResNet-50, VGG16. Using the new VisionTransformer model in the problem of ransomware classification.""")

    st.markdown("The full report could be found " + f'<a href="data:file/pdf" download="utils/peFeaturesAdd_3 - ENGLISH.pdf">here.</a>', unsafe_allow_html=True)

    st.write("Authors of the work: Dam Quang Tien, Nguyen Nghia Thinh, Le Viet Trung")

    st.write("Faculty: Dr. Le Tran Duc")

    st.write("## We need a Portable Executable 32bit file as the input of the prediction pipeline! ##")

    file = st.file_uploader(label="Upload file")

    ok = st.button("Let's predict!")

    if ok:
        tempfile = save_uploadedfile(file, tempfolder)
        # try:
        if True:
            saved = createRGBImageWithSectionAndPEBest(tempfile, withPe=True)

            extract = extract_infos(tempfile)

            col1, col2 = st.columns(2)

            with col1:

                st.write("### File's PE header information ###")

                df = pd.DataFrame(extract).T
                df.columns = columns
                df = df.T
                df.columns = ['Value']
                ta = df.astype(str)
                st.table(ta)

            with col2:

                st.write("### Preprocessing")
                st.write("The pipeline first extract PE information from the file.\n"
                         "Then take only 5 most impact features from that information to encode into the image.\n"
                         "Those are 'SectionMaxRawsize', 'MajorLinkerVersion', 'DllCharacteristics', "
                         "'SectionsMaxEntropy', 'AddressOfEntryPoint'.")
                image = Image.open(saved)
                st.image(image, caption=f"File's representative image with section markers and 5 color encoded PE features.", width=700)

                pro, pre = predict_single_file(weight_dir=weight_imcec_dir, image_path=saved, cuda=False)
                st.write("### Model's prediction")
                predict = "**not ransomware**"

                if pre == 1:
                    predict = "**ransomware**"

                st.write(f"The file is {predict} with probability **{pro * 100}%**")
        # except:
        #     st.write("The input file is not PE32 or corrupted!")

