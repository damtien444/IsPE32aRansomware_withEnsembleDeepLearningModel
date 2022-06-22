import base64
import os
from pathlib import Path

import pandas as pd
from PIL import Image

import streamlit as st
from predict import predict_single_file
from utils.Extract import extract_infos, columns
from utils.preprocessing import createRGBImageWithSectionAndPEBest



weight_file_id = "1ybTh2BTrrH9fc48h5hsdU4PNhhJwf8sM"
weight_link = "https://drive.google.com/file/d/1ybTh2BTrrH9fc48h5hsdU4PNhhJwf8sM/view?usp=sharing"
tempfolder = os.getcwd() + os.sep + "temp"
weight_imcec_dir= r"result/exp/best.pt"

# def create_download_link(val, filename):
#     b64 = base64.b64encode(val)  # val looks like b'...'
#     return f'<a href="data:application/octet-stream;base64,{b64.decode()}" download="{filename}.pdf">Download file</a>'


def save_uploadedfile(uploadedfile, tempfolder):
    with open(os.path.join(tempfolder, uploadedfile.name), "wb") as f:
        f.write(uploadedfile.getbuffer())
    return os.path.join(tempfolder, uploadedfile.name)


def show_predict_page():

    st.title("Tệp tin này có phải là mã độc tống tiền?")

    st.write("Để phân biệt được một tệp thực thi PE có phải là một ransomware thì yêu cầu một quá trình phân tích các đặc trưng của tệp tin và hiểu các IOCs của mã độc tống tiền.")

    st.write("Công cụ này sử dụng một quy trình tiền xử lý tệp tin kết hợp thông tin từ PE header và "
             "một mô hình deeplearning kết hợp (từ VGG16, Resnet50).")

    st.write("Có thể giúp các chuyên gia/người không "
             "có chuyên môn phân định được dễ dàng các mã độc, giảm thời gian phản ứng trong quy trình "
             "phòng chống tấn công mạng máy tính.")

    st.write("Người thực hiện đồ án: **Đàm Quang Tiến**")

    st.write("Xin cảm sự hướng dẫn của thầy Nguyễn Văn Nguyên hoàn thành đồ án, thầy Lê Trần Đức và các thầy trong hội đồng phản biện hội nghị cùng các cộng sự đã cùng em hoàn thành nghiên cứu này.")

#     st.write("""The main contributions to this study include:\n
# 1.   Classification of ransomware uses images containing information from PE headers, thereby helping to increase the similarity between samples of the same variant strain.\n
# 2.   Select features from PE headers using machine learning models and encode them into images representing ransomware samples.\n
# 3.   Building a combination model from famous CNN networks such as ResNet-50, VGG16. Using the new VisionTransformer model in the problem of ransomware classification.""")

    with open(r"utils/peFeaturesAdd_3 - ENGLISH.pdf", "rb") as f:
        base64_pdf = base64.b64encode(f.read()).decode('utf-8')
        st.write("### Đồ án này dựa trên bài nghiên cứu sau:")
        st.markdown(f'<embed src="data:application/pdf;base64,{base64_pdf}" target="_blank" width="1000" height="200" type="application/pdf">', unsafe_allow_html=True)


    st.write("## We need a Portable Executable 32bit file as the input of the prediction pipeline! ##")

    file = st.file_uploader(label="Upload file")

    ok = st.button("Let's predict!")

    if ok:
        tempfile = save_uploadedfile(file, tempfolder)
        try:
        # if True:
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
        except:
            st.write("The input file is not PE32 or corrupted!")

