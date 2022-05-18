import math
import os
import time

import cv2
import matplotlib.pyplot as plt
import numpy as np
import torchvision.transforms as transforms
from PIL import Image

from utils.help_function import color_scheme, minmaxnorm, extract_best_feature, find_sections, cal_thickness, \
    gen_vertical_lines, color_name
from utils.turbo_color_scheme import turbo_colormap_data


def load_image(image, device):
    means = (0.485, 0.456, 0.406)
    stds = (0.229, 0.224, 0.225)
    loader = transforms.Compose([transforms.ToTensor(), transforms.Normalize(means, stds)])
    return loader(image).to(device)

def read_image(path, device):
    image = cv2.imread(path)
    image = cv2.resize(image, (224,224))
    image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    return load_image(image, device)


def plot_predict_results(list_score, labels, args):
    path_test = args.test_dir
    save_path = path_test.replace(path_test.split('/')[-1], '') + 'predict.png'

    plt.figure(figsize=(15, 15))
    for row in range(len(labels)):
        for col in range(len(labels)):
            plt.annotate(str(np.round(list_score[row][col], 3)), xy=(col, row), ha='center', va='center')
    plt.imshow(list_score)
    plt.yticks(np.arange(12), labels)
    plt.xticks(np.arange(12), labels)
    plt.colorbar()
    plt.savefig(save_path)

def getBinaryData(filename):
    """
    Extract byte values from binary executable file and store them into list
    :param filename: executable file name
    :return: byte value list
    """
    path = r'{}'.format(filename)

    binary_values = []
    try:
       with open(path, 'rb') as fileobject:

            # read file byte by byte
            data = fileobject.read(1)

            while data != b'':
                binary_values.append(ord(data))
                data = fileobject.read(1)

            return binary_values

    except Exception as E:
        print(E)
        return False

def get_size(data_length, width=None):
    # source Malware images: visualization and automatic classification by L. Nataraj
    # url : http://dl.acm.org/citation.cfm?id=2016908

    if width is None:  # with don't specified any with value

        size = data_length

        if (size < 10240):
            width = 32
        elif (10240 <= size <= 10240 * 3):
            width = 64
        elif (10240 * 3 <= size <= 10240 * 6):
            width = 128
        elif (10240 * 6 <= size <= 10240 * 10):
            width = 256
        elif (10240 * 10 <= size <= 10240 * 20):
            width = 384
        elif (10240 * 20 <= size <= 10240 * 50):
            width = 512
        elif (10240 * 50 <= size <= 10240 * 100):
            width = 768
        else:
            width = 1024

        height = int(size / width) + 1

    else:
        width = int(math.sqrt(data_length)) + 1
        height = width

    return (width, height)

def save_file(image_name, data, size, image_type):
    # try:
    image = Image.new(image_type, size)
    image.putdata(data)

    # setup output filename
    dir = "temp"
    imagename = os.getcwd() + os.sep + dir + os.sep + str(float(time.time())) + ".png"
    print(imagename)

    os.makedirs(os.path.dirname(imagename), exist_ok=True)

    image.save(imagename)
    print('The file', imagename, 'saved.')

    return imagename

def createRGBImageWithSectionAndPEBest(filename, width=None, withPe=False):
    """
    Create RGB image from 24 bit binary data 8bit Red, 8 bit Green, 8bit Blue
    :param filename: image filename
    """
    index = 0
    rgb_data = []

    # Read binary file
    binary_data = getBinaryData(filename)
    try:
        # pe_best = minmaxnorm(extract_best_feature(filename))
        pe_best = minmaxnorm(extract_best_feature(filename, type_best=3))

    except Exception as e:
        print(e)
        return
    sections = find_sections(filename)
    if sections is None:
        return
    thickness = round(cal_thickness(len(binary_data), 1))
    if thickness == 0:
        thickness = 1

    if thickness > 10:
        print('too large thickness')
        thickness = 10

    if binary_data:

        # Create R,G,B pixels
        while (index) < len(binary_data):
            R = binary_data[index]
            G = binary_data[index]
            B = binary_data[index]
            index += 1
            rgb_data.append((R, G, B))

        size = get_size(len(rgb_data), width)

        # if not valid_size(size):
        #     print('not_valid_size', family_name, filename)

        column_of_pe = gen_vertical_lines(binary_data, size[0], size[1], thickness, num=len(pe_best.keys()))
        color = []
        for feature, value in pe_best.items():
            temp = int(value * 255)
            if temp > 255:
                temp = 255
            elif temp < 0:
                temp = 0
            turbo = []
            # turbo = turbo_colormap_data[temp].copy()
            turbo = turbo_colormap_data[temp].copy()
            for i in range(len(turbo)):
                val = turbo[i]
                val *= 255
                turbo[i] = int(val)
            turbo = tuple(turbo)
            color.append(turbo)
        i = 0
        for pe_column, cols in column_of_pe.items():
            color_in = color[i]
            for row in cols:
                for index in row:
                    if withPe:
                        rgb_data[index] = color_in
            i += 1

        size = get_size(len(rgb_data), width)

        count = 0
        for sectionname, secioninfo in sections.items():

            pos = secioninfo[0] // size[0]
            # print(pos)
            if sectionname == ".text":
                count += 1
                for i in range(size[0]):
                    for j in range(thickness):
                        rgb_data[(pos + j) * size[0] + i] = color_scheme["RED"]
            else:
                count += 1
                color_ind = count % len(color_name)
                print(pos, size, len(rgb_data), thickness)
                for i in range(size[0]):
                    for j in range(thickness):
                        # rgb_data[(pos+j)*size[0] + i] = color[color_name[color_ind]]
                        if (pos + j) * size[0] + i < len(rgb_data):
                            rgb_data[(pos + j) * size[0] + i] = color_scheme[color_name[color_ind]]

        # if valid_size(size):
        saved = save_file(filename, rgb_data, size, 'RGB')

        return saved

