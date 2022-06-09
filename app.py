
from predict_page import show_predict_page
weight_file_id = "1ybTh2BTrrH9fc48h5hsdU4PNhhJwf8sM"
weight_link = "https://drive.google.com/file/d/1ybTh2BTrrH9fc48h5hsdU4PNhhJwf8sM"
tempfolder = r"E:\Malware Image Based\drive-download-20220515T075039Z-001\temp"
weight_imcec_dir= r"result/exp/best.pt"


# if not Path(weight_imcec_dir).exists():
#     with st.spinner("Downloading model... this may take awhile! \n Don't stop it!"):
#         gdown.download(weight_link, weight_imcec_dir)
show_predict_page()