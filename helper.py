import os
from queue import Queue
from threading import Thread

from PIL import Image

from utils.Extract import extract_infos
from utils.preprocessing import getBinaryData, get_size


def createRGBImage(family_name, file_name, inx, width=None):
    """
    Create RGB image from 24 bit binary data 8bit Red, 8 bit Green, 8bit Blue
    :param family_name: family of image file
    :param file_name: name of malware
    :param inx: index of the loop create image
    """
    index = 0
    rgb_data = []

    # Read binary file
    binary_data = getBinaryData(file_name)

    if binary_data:

        # Create R,G,B pixels
        while index < len(binary_data):
            R = binary_data[index]
            G = binary_data[index]
            B = binary_data[index]
            index += 1
            rgb_data.append((R, G, B))

        size = get_size(len(rgb_data), width)
        save_file_format_name(family_name, file_name, rgb_data, size, 'RGB', inx)


def save_file_format_name(family_name, file_name, data, size, image_type, inx):
    """
    Create RGB image with name format
    :param family_name: family of image file
    :param file_name: name of malware
    :param data: data to convert to image
    :param size: size of image
    :param image_type: type image (RGB,...)
    :param inx: index of the loop create image
    """
    image = Image.new(image_type, size)
    image.putdata(data)

    # setup output file_name
    dir = "Trung_1"
    # image_name = os.getcwd() + os.sep + dir + os.sep + str(float(time.time())) + ".png"
    image_name = f"{os.getcwd()}\\{dir}\\{family_name}_{inx}.png"
    print(image_name)

    # os.makedirs(os.path.dirname(family_name), exist_ok=True)

    image.save(image_name)
    print('The file', image_name, 'saved.')

    return image_name

def run_multi(file_queue, ff):
    while not file_queue.empty():
        family, file_name, save_folder, inx = file_queue.get()
        try:
            results = extract_infos(file_name)
            results.append(f"{family}_{inx}")
            ff.write('|'.join(map(lambda x: str(x), results)) + "\n")
            createRGBImage(family, file_name, inx)
        except:
            print(f"{family}_{inx} has bad pe header, excluded")

        file_queue.task_done()

def loop_through_srcfolder(root_folder, save_path=None):
    file_queue = Queue()
    inx = 0
    prev_fa = ""
    for subdir, dirs, files in os.walk(root_folder):
        for file in files:
            family = subdir[len(root_folder)+1:]
            if prev_fa != family:
                prev_fa = family
                inx = 0
            inx += 1
            # print(root_folder, subdir+os.sep+file)
            file_queue.put((family, subdir+os.sep+file, save_path, inx))
            # print((family, subdir+os.sep+file, save_path, inx))

    return file_queue

def file_extr_declare(filename="classification_ransomware_family.csv"):
    output = filename
    csv_delimiter = "|"
    columns = [
        "Name", "md5", "Machine", "SizeOfOptionalHeader", "Characteristics", "MajorLinkerVersion", "MinorLinkerVersion",
        "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode",
        "BaseOfData",
        "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
        "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion", "SizeOfImage",
        "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
        "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes", "SectionsNb",
        "SectionsMeanEntropy",
        "SectionsMinEntropy", "SectionsMaxEntropy", "SectionsMeanRawsize", "SectionsMinRawsize", "SectionMaxRawsize",
        "SectionsMeanVirtualsize", "SectionsMinVirtualsize", "SectionMaxVirtualsize", "ImportsNbDLL", "ImportsNb",
        "ImportsNbOrdinal", "ExportNb", "ResourcesNb", "ResourcesMeanEntropy", "ResourcesMinEntropy",
        "ResourcesMaxEntropy",
        "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize", "LoadConfigurationSize", "VersionInformationSize",
        "legitimate"]
    ff = open(output, "a")
    ff.write(csv_delimiter.join(columns) + "\n")
    return ff

if __name__ == '__main__':
    list_file = loop_through_srcfolder(r"E:\Malware Image Based\2022-08-newly downloaded dataset\jsonGenTest")
    ff = file_extr_declare()
    for index in range(8):
        thread = Thread(target=run_multi, args=(list_file, ff))
        thread.daemon = True
        thread.start()
    list_file.join()
    ff.close()


    # createRGBImage("Babuk", r"E:\Malware Image Based\ransom_dataset_anhLuong\_Dataset\Babuk\1b9412ca5e9deb29aeaa37be05ae8d0a8a636c12fdff8c17032aa017f6075c02.exe", 1)
