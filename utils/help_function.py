import json

import pefile

from utils.Extract import extract_infos

color_scheme = {
    "RED": (255, 0, 24),
    "ORANGE": (255, 165, 44),
    "YELLOW": (255, 255, 65),
    "GREEN": (0, 128, 24),
    "BLUE": (0, 0, 249),
    "VIOLET": (134, 0, 125)
}

color = {
    "RED": (255, 0, 24),
    "ORANGE": (255, 165, 44),
    "YELLOW": (255, 255, 65),
    "GREEN": (0, 128, 24),
    "BLUE": (0, 0, 249),
    "VIOLET": (134, 0, 125)
}

color_name = []
for key in color.keys():
    color_name.append(key)

def minmaxnorm(best_feature):
    with open(r"utils/featureRange.json") as file:
        featureRange = json.load(file)

    norm = {}
    for key, val in best_feature.items():
        maxx, minn, mean, std = featureRange[key]
        _ = (val - minn) / (maxx - minn)
        norm[key] = _

    return norm

def extract_best_feature(filepath, type_best=3):
    val = {}
    extract = extract_infos(filepath)

    collumns_name = ['Name', 'md5', 'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
                     'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
                     'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment',
                     'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion',
                     'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfImage',
                     'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics', 'SizeOfStackReserve',
                     'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes',
                     'SectionsNb', 'SectionsMeanEntropy', 'SectionsMinEntropy', 'SectionsMaxEntropy',
                     'SectionsMeanRawsize', 'SectionsMinRawsize', 'SectionMaxRawsize', 'SectionsMeanVirtualsize',
                     'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal',
                     'ExportNb', 'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy',
                     'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize',
                     'VersionInformationSize', 'legitimate']

    if type_best == 0:
        with open('randomforrest.json') as json_file:
            bestFeature = json.load(json_file)
            for name in bestFeature:
                val[name] = extract[collumns_name.index(name)]

        return val

    elif type_best == 1:
        with open('extratree.json') as json_file:
            bestFeature = json.load(json_file)
            for name in bestFeature:
                val[name] = extract[collumns_name.index(name)]

        return val

    elif type_best == 2:
        with open('catboost.json') as json_file:
            bestFeature = json.load(json_file)
            for name in bestFeature:
                val[name] = extract[collumns_name.index(name)]

        return val

    elif type_best == 3:

        best_feature = ['SectionMaxRawsize',
                        'MajorLinkerVersion',
                        'DllCharacteristics',
                        'SectionsMaxEntropy',
                        'AddressOfEntryPoint'
                        ]

        for name in best_feature:
            val[name] = extract[collumns_name.index(name)]
        return val

def find_sections(path):
    try:
        pe = pefile.PE(path)
        section_l = {}

        for section in pe.sections:
            name = section.Name.decode("UTF-8").strip("\0")
            # print(name)
            # print("\tVirtual Address: ", section.PointerToRawData)
            # # print("\tVirtual Size: ", section.Misc_VirtualSize)
            # print("\tRaw Size: ", section.SizeOfRawData)
            section_l[name] = [section.PointerToRawData, section.SizeOfRawData]

        return section_l
    except Exception as err:
        print(err)

def cal_thickness(file_size, interval_size):
    return ((file_size / 1024) / 50) * interval_size

def gen_vertical_lines(data, width, height, thickness, num=10):
    # width, height = get_size(len(data))
    spacious = (width - thickness) / (num - 1)
    list = {}
    for i in range(num):
        list[i] = []
        for j in range(height):
            _ = []
            for k in range(thickness):
                if width * j + k + spacious * i < len(data):
                    _.append(width * j + k + int(spacious * i))
            list[i].append(_)

    return list