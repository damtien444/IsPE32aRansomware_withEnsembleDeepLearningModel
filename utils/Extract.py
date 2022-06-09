import os
from queue import Queue

import pefile
import hashlib
import array
import math

# import ransom_label
# from binary_to_image.binary_to_image import get_size, getBinaryData, valid_size

def get_md5(fname):
    hash_md5 = hashlib.md5()
    cout = 0
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), "b"):
            hash_md5.update(chunk)
            cout = cout + 1
            if cout == 1000:
                break
    return hash_md5.hexdigest()


def get_entropy(data):
    if len(data) == 0: return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1
    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
    entropy -= p_x * math.log(p_x, 2)
    return entropy


def get_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                   resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception:
            return resources
    return resources


def get_version_info(pe):
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


def extract_infos(fpath):
    results = []
    results.append(os.path.basename(fpath))
    results.append(get_md5(fpath))
    pe = pefile.PE(fpath)
    results.append(pe.FILE_HEADER.Machine)
    results.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    results.append(pe.FILE_HEADER.Characteristics)
    results.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    results.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    results.append(pe.OPTIONAL_HEADER.SizeOfCode)
    results.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
    results.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
    results.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    results.append(pe.OPTIONAL_HEADER.BaseOfCode)
    try:
        results.append(pe.OPTIONAL_HEADER.BaseOfData)
    except AttributeError:
        results.append(0)
    results.append(pe.OPTIONAL_HEADER.ImageBase)
    results.append(pe.OPTIONAL_HEADER.SectionAlignment)
    results.append(pe.OPTIONAL_HEADER.FileAlignment)
    results.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    results.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    results.append(pe.OPTIONAL_HEADER.MajorImageVersion)
    results.append(pe.OPTIONAL_HEADER.MinorImageVersion)
    results.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    results.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
    results.append(pe.OPTIONAL_HEADER.SizeOfImage)
    results.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    results.append(pe.OPTIONAL_HEADER.CheckSum)
    results.append(pe.OPTIONAL_HEADER.Subsystem)
    results.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    results.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
    results.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
    results.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
    results.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    results.append(pe.OPTIONAL_HEADER.LoaderFlags)
    results.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    results.append(len(pe.sections))
    entropy = map(lambda x: x.get_entropy(), pe.sections)
    set_entropy = set(entropy)
    if (len(set_entropy) > 0):
        results.append(sum(set_entropy) / float(len(set_entropy)))
        results.append(min(set_entropy))
        results.append(max(set_entropy))
    else:
        results.append(0)
        results.append(0)
        results.append(0)
    raw_sizes = map(lambda x: x.SizeOfRawData, pe.sections)
    setsRawSizes = set(raw_sizes)
    if (len(setsRawSizes) > 0):
        results.append(sum(setsRawSizes) / float(len(setsRawSizes)))
        results.append(min(setsRawSizes))
        results.append(max(setsRawSizes))
    else:
        results.append(0)
        results.append(0)
        results.append(0)
    virtual_sizes = map(lambda x: x.Misc_VirtualSize, pe.sections)
    listsVirtualSizes = list(virtual_sizes)
    if (len(listsVirtualSizes) > 0):
        results.append(sum(listsVirtualSizes) / float(len(listsVirtualSizes)))
        results.append(min(listsVirtualSizes))
        results.append(max(listsVirtualSizes))
    else:
        results.append(0)
        results.append(0)
        results.append(0)
    # Imports
    try:
        results.append(len(pe.DIRECTORY_ENTRY_IMPORT))
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        results.append(len(imports))
        fil = filter(lambda x: x.name is None, imports)
        results.append(len(set(fil)))
    except AttributeError:
        results.append(0)
        results.append(0)
        results.append(0)
    # Exports
    try:
        results.append(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
    except AttributeError:
        # No export
        results.append(0)
    # Resources
    resources = get_resources(pe)
    results.append(len(resources))
    if len(resources) > 0:
        ResourceEntropy = set(map(lambda x: x[0], resources))
        results.append(sum(ResourceEntropy) / float(len(ResourceEntropy)))
        results.append(min(ResourceEntropy))
        results.append(max(ResourceEntropy))
        ResourceSizes = set(map(lambda x: x[1], resources))
        results.append(sum(ResourceSizes) / float(len(ResourceSizes)))
        results.append(min(ResourceSizes))
        results.append(max(ResourceSizes))
    else:
        results.append(0)
        results.append(0)
        results.append(0)
        results.append(0)
        results.append(0)
        results.append(0)

    # Load configuration size
    try:
        results.append(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size)
    except AttributeError:
        results.append(0)

    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        results.append(len(version_infos.keys()))
    except AttributeError:
        results.append(0)
    return results

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
    "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize", "LoadConfigurationSize", "VersionInformationSize"]

#
# if __name__ == '__main__':
#     output = "classification_ransomware_malware.csv"
#     csv_delimiter = "|"
#     columns = [
#         "Name", "md5", "Machine", "SizeOfOptionalHeader", "Characteristics", "MajorLinkerVersion", "MinorLinkerVersion",
#         "SizeOfCode", "SizeOfInitializedData", "SizeOfUninitializedData", "AddressOfEntryPoint", "BaseOfCode",
#         "BaseOfData",
#         "ImageBase", "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
#         "MajorImageVersion", "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion", "SizeOfImage",
#         "SizeOfHeaders", "CheckSum", "Subsystem", "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
#         "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags", "NumberOfRvaAndSizes", "SectionsNb",
#         "SectionsMeanEntropy",
#         "SectionsMinEntropy", "SectionsMaxEntropy", "SectionsMeanRawsize", "SectionsMinRawsize", "SectionMaxRawsize",
#         "SectionsMeanVirtualsize", "SectionsMinVirtualsize", "SectionMaxVirtualsize", "ImportsNbDLL", "ImportsNb",
#         "ImportsNbOrdinal", "ExportNb", "ResourcesNb", "ResourcesMeanEntropy", "ResourcesMinEntropy",
#         "ResourcesMaxEntropy",
#         "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize", "LoadConfigurationSize", "VersionInformationSize",
#         "legitimate"]
#     ff = open(output, "a")
#     ff.write(csv_delimiter.join(columns) + "\n")
#     k = 0
#
#     # input_dir = "C:\WINDOWS\System32"
#     input_dir = "E:\\Malware Image Based\\ransom_dataset_anhLuong\\_Dataset"
#     file_queue = []
#     # file_queue = ['F:\\Malware Image Based\\Dataset\\VirusShare_cbed014422cad09cbcd62ced466c11f1', 'F:\\Malware Image Based\\Dataset\\VirusShare_9d6a315376f8bc8a7537ecb759511bca', 'F:\\Malware Image Based\\Dataset\\VirusShare_ff86c3227c899b588f9255efdfda8ba0', 'F:\\Malware Image Based\\Dataset\\VirusShare_ff290cfd5e15607d46aeb4b6f6028013', 'F:\\Malware Image Based\\Dataset\\VirusShare_fee2d2e740434ec28c1e5c51f4b7cb98', 'F:\\Malware Image Based\\Dataset\\VirusShare_fecb35cbffb8286cd44285474147e1ea', 'F:\\Malware Image Based\\Dataset\\VirusShare_fe6a3813b469a93baecbffc1daf87aad', 'F:\\Malware Image Based\\Dataset\\VirusShare_fdb5559b92d60219a9b307fc04dfdec0', 'F:\\Malware Image Based\\Dataset\\VirusShare_fd9a59c96eb513fc3792999206ae0535', 'F:\\Malware Image Based\\Dataset\\VirusShare_fd8b5b86571606c1767118b4a82209eb', 'F:\\Malware Image Based\\Dataset\\VirusShare_fd4b5e44dbd622c44784de244da161c0', 'F:\\Malware Image Based\\Dataset\\VirusShare_fd3487ec76291d233faa6af0b9afec1e', 'F:\\Malware Image Based\\Dataset\\VirusShare_fca28550e1952a01ca801630f587e3a0', 'F:\\Malware Image Based\\Dataset\\VirusShare_fb639bd96a999b87598f4a93e880dce0', 'F:\\Malware Image Based\\Dataset\\VirusShare_fb0a4d1ccad1e4dd5536b0566ac4d5d6', 'F:\\Malware Image Based\\Dataset\\VirusShare_fae739b9544c6b6d8e69d2adea8a6035', 'F:\\Malware Image Based\\Dataset\\VirusShare_fa6db4d81ca9212ab0c07a8f9ee6af40', 'F:\\Malware Image Based\\Dataset\\VirusShare_f9b54a91e372b307464023fa28647d20', 'F:\\Malware Image Based\\Dataset\\VirusShare_f8a78136c3ce5105ccca213190d68f90', 'F:\\Malware Image Based\\Dataset\\VirusShare_f8a1bf1064eaba4a87a8a9535c4ddd80', 'F:\\Malware Image Based\\Dataset\\VirusShare_f6b8209d624b32f118ae977bb1c4dc7c', 'F:\\Malware Image Based\\Dataset\\VirusShare_f58fd81156061f49a70b5f29c064d4e3', 'F:\\Malware Image Based\\Dataset\\VirusShare_f4f07407455645d129a1ce3682648c5d', 'F:\\Malware Image Based\\Dataset\\VirusShare_f4edbc9b0ccc093d87b780697ef59bc3', 'F:\\Malware Image Based\\Dataset\\VirusShare_f1f74630b4ef1ccf628f4cdffdd47978', 'F:\\Malware Image Based\\Dataset\\VirusShare_f041a0331c24d4864022a623ff3ec2ac', 'F:\\Malware Image Based\\Dataset\\VirusShare_ef6feec84aedb43887c155ff47b9cea0', 'F:\\Malware Image Based\\Dataset\\VirusShare_ef19c077fd04ff87d484ee02281eddc8', 'F:\\Malware Image Based\\Dataset\\VirusShare_ee9a06b33b17146dd2ff0901c07f7cd0', 'F:\\Malware Image Based\\Dataset\\VirusShare_ee3bcc6dad09a6bde834f04ee8326d03', 'F:\\Malware Image Based\\Dataset\\VirusShare_edde816464c762a132adfce1be13caf1', 'F:\\Malware Image Based\\Dataset\\VirusShare_eda57390a4d606614350a9f7786ec54b', 'F:\\Malware Image Based\\Dataset\\VirusShare_ed012d82d79e27cbe982090b3916f29c', 'F:\\Malware Image Based\\Dataset\\VirusShare_eb80c3ff28ad4377eefa8a8176636e45', 'F:\\Malware Image Based\\Dataset\\VirusShare_eb25eff06faa9b243ee6551d72da0c90', 'F:\\Malware Image Based\\Dataset\\VirusShare_eac12136c2b70ebfd42942f7b09445b0', 'F:\\Malware Image Based\\Dataset\\VirusShare_ea696df85fd332ba3e9bcf3bee979ec4', 'F:\\Malware Image Based\\Dataset\\VirusShare_ea5d9fb59388165cf2a0c649f76ad060', 'F:\\Malware Image Based\\Dataset\\VirusShare_e9f108bfe4f247db9597aa1d6d408cb9', 'F:\\Malware Image Based\\Dataset\\VirusShare_e9d0a12ec833177b3feeefeca45a93bc', 'F:\\Malware Image Based\\Dataset\\VirusShare_e77990d560b1aaf3691d6cacfcb24d3e', 'F:\\Malware Image Based\\Dataset\\VirusShare_e6a6996f7a2f9f05ee3a094e84f33df9', 'F:\\Malware Image Based\\Dataset\\VirusShare_e582e228687fe8ab4cd2684b1b37c129', 'F:\\Malware Image Based\\Dataset\\VirusShare_e22a23d4f469f9237d860067ec6b8d9c', 'F:\\Malware Image Based\\Dataset\\VirusShare_e1ea587b38df8ad08869ed7efdd6ae60', 'F:\\Malware Image Based\\Dataset\\VirusShare_e13937fadd55a8929414663c6772bec2', 'F:\\Malware Image Based\\Dataset\\VirusShare_e05698a733c8784e861f1024542e4490', 'F:\\Malware Image Based\\Dataset\\VirusShare_def12b34ffa71ec4577150f7efa38d78', 'F:\\Malware Image Based\\Dataset\\VirusShare_dd5aa4f24858d367049d52f56a1ee450', 'F:\\Malware Image Based\\Dataset\\VirusShare_dd05424bef4bbc1e56477638270a0bb2', 'F:\\Malware Image Based\\Dataset\\VirusShare_dcf98565abfb8571ee02299da52267f1', 'F:\\Malware Image Based\\Dataset\\VirusShare_dcc21e43873910f25060196fbe0f3680', 'F:\\Malware Image Based\\Dataset\\VirusShare_dbec5d65ea476255c4bb6dead34b161a', 'F:\\Malware Image Based\\Dataset\\VirusShare_dbaca94c4866aa3c5ee26edd04acdc20', 'F:\\Malware Image Based\\Dataset\\VirusShare_dba4baf6e8e25d020dac77beaa09b0c4', 'F:\\Malware Image Based\\Dataset\\VirusShare_d9ba6f3238a84859c5090848f29216f0', 'F:\\Malware Image Based\\Dataset\\VirusShare_d82f653d64f0836f03976525f1daed78', 'F:\\Malware Image Based\\Dataset\\VirusShare_d7cc9f0b44f8dd3dd806d1d2cc0b1f77', 'F:\\Malware Image Based\\Dataset\\VirusShare_d7510f91496aa7c286ff1b4ccebee1ca', 'F:\\Malware Image Based\\Dataset\\VirusShare_d6b2eb7af45b9a2c8cce9ddd70224600', 'F:\\Malware Image Based\\Dataset\\VirusShare_d51076c3b06efdce0dcdf430faded250', 'F:\\Malware Image Based\\Dataset\\VirusShare_d50d64ec5dd85b24cf5b20f2dc9cb31b', 'F:\\Malware Image Based\\Dataset\\VirusShare_d4e268d9f814b570d8610ccb3fe88156', 'F:\\Malware Image Based\\Dataset\\VirusShare_d465852bcf7d6f2c3c79cc266186452f', 'F:\\Malware Image Based\\Dataset\\VirusShare_d3aa34ec10b0fe1efa2e1e17058c7697', 'F:\\Malware Image Based\\Dataset\\VirusShare_d3903034ac7b2f86269c9303a1727957', 'F:\\Malware Image Based\\Dataset\\VirusShare_d36cf9076dcdd9715c70d1ec0d721da4', 'F:\\Malware Image Based\\Dataset\\VirusShare_d2b4547702fbe48ea8c347abc906fea0', 'F:\\Malware Image Based\\Dataset\\VirusShare_d29df553f0437db7a1c0245220970d3e', 'F:\\Malware Image Based\\Dataset\\VirusShare_d2660499dfe30ca43ac5e48d8ca18720', 'F:\\Malware Image Based\\Dataset\\VirusShare_d151d9b2ba9b9e4d4be12c97c82e6a74', 'F:\\Malware Image Based\\Dataset\\VirusShare_d02e01a2707d17efef15101334e9ed77', 'F:\\Malware Image Based\\Dataset\\VirusShare_cfdbdd58ecc4c5115150159875fb065a', 'F:\\Malware Image Based\\Dataset\\VirusShare_cf45ee0c64baf0cb115433284675da70', 'F:\\Malware Image Based\\Dataset\\VirusShare_cf37f9bffc95b010203b637aeefc302c', 'F:\\Malware Image Based\\Dataset\\VirusShare_cefb069ed9f2e0b8feb1246503d087e6', 'F:\\Malware Image Based\\Dataset\\VirusShare_cd586c08a2c9b0c0afc9eaac5ddb715c', 'F:\\Malware Image Based\\Dataset\\VirusShare_cd322443981b3cf351d85d1c9148ae3a', 'F:\\Malware Image Based\\Dataset\\VirusShare_ccd45af7a6e7a161333afb64545249eb', 'F:\\Malware Image Based\\Dataset\\VirusShare_cc729787e93c079d2327bf9c388cdeae', 'F:\\Malware Image Based\\Dataset\\VirusShare_cc0e656e5e332b12691d29447984fc90', 'F:\\Malware Image Based\\Dataset\\VirusShare_cbedae7cea2b7d328cb00bb44699cd39', 'F:\\Malware Image Based\\Dataset\\VirusShare_cab3e7c8b95b27ac3f1fefc76d080236', 'F:\\Malware Image Based\\Dataset\\VirusShare_ca6297e4dfa8c185c526b16f15af8de9', 'F:\\Malware Image Based\\Dataset\\VirusShare_ca59e577821681fc1f7f4330e6a83482', 'F:\\Malware Image Based\\Dataset\\VirusShare_ca1aabc50084e7c923369f3579521630', 'F:\\Malware Image Based\\Dataset\\VirusShare_ca185d9f75f3fa91b87cac63a7e6c500', 'F:\\Malware Image Based\\Dataset\\VirusShare_c93babd447af221a55b0bef48675252c', 'F:\\Malware Image Based\\Dataset\\VirusShare_c74674bbfdf40e51b53233ce822ace58', 'F:\\Malware Image Based\\Dataset\\VirusShare_c6b7a676697f084f2f58808d2ad4c480', 'F:\\Malware Image Based\\Dataset\\VirusShare_c6056591a33c01285cd6a2df2c8b00dd', 'F:\\Malware Image Based\\Dataset\\VirusShare_c5eb5a40c80f08085f56486e8c0e4cd0', 'F:\\Malware Image Based\\Dataset\\VirusShare_c5e51b9fda3437488a4c171cbaa99e32', 'F:\\Malware Image Based\\Dataset\\VirusShare_c5dcc10afbaf09e919297906b32b0710', 'F:\\Malware Image Based\\Dataset\\VirusShare_c5bf87e5e5bb7555f1c4848a1757d8f0', 'F:\\Malware Image Based\\Dataset\\VirusShare_c461c15f83938a50074494958481be8c', 'F:\\Malware Image Based\\Dataset\\VirusShare_c373d9b1e90cd8ff158ec453dea3cd08', 'F:\\Malware Image Based\\Dataset\\VirusShare_c2edb532a4ee6ff1f33b37959a188742', 'F:\\Malware Image Based\\Dataset\\VirusShare_c1d90fef038a7a9922881a317d5207e0', 'F:\\Malware Image Based\\Dataset\\VirusShare_c147ebd33231490939a1d7c83ae2cbcd', 'F:\\Malware Image Based\\Dataset\\VirusShare_c12cf8bf7edea659f580f7877361c060', 'F:\\Malware Image Based\\Dataset\\VirusShare_c0dfffaef78ff8c75a2de164153dc7f0', 'F:\\Malware Image Based\\Dataset\\VirusShare_bf2aea256b842bfac940e9145776c081', 'F:\\Malware Image Based\\Dataset\\VirusShare_bec4c649816271500a3ce3227fb03290', 'F:\\Malware Image Based\\Dataset\\VirusShare_be7d3d64d725ad0dc12f7a6ed273a315', 'F:\\Malware Image Based\\Dataset\\VirusShare_be61da73c9848ca6df8ef011b65afe67', 'F:\\Malware Image Based\\Dataset\\VirusShare_bd0ab0649e4860d10eb59de87655e910', 'F:\\Malware Image Based\\Dataset\\VirusShare_bc2909bebc10282a052d5b80f6627e82', 'F:\\Malware Image Based\\Dataset\\VirusShare_bbe523cbf6a11f8d7f721abf85686bc1', 'F:\\Malware Image Based\\Dataset\\VirusShare_bb06ff0397364787effac0400f6be46c', 'F:\\Malware Image Based\\Dataset\\VirusShare_ba6e43efa066fd43eb0af7cf5c40c000', 'F:\\Malware Image Based\\Dataset\\VirusShare_ba3d66958ef0e28da4c78b18ed43cced', 'F:\\Malware Image Based\\Dataset\\VirusShare_b93c6d3b1e2ebe21a6092badc3e4f7b2', 'F:\\Malware Image Based\\Dataset\\VirusShare_b92329ab86b839d0bc8e648158945243', 'F:\\Malware Image Based\\Dataset\\VirusShare_b83d1b728c724286c28731a558275a20', 'F:\\Malware Image Based\\Dataset\\VirusShare_b7c15a8a1f444f150a0b01c28c65c3da', 'F:\\Malware Image Based\\Dataset\\VirusShare_b7aad514ea58c59903fcad313d73edbf', 'F:\\Malware Image Based\\Dataset\\VirusShare_b54801bd87941de95768e507c1a51990', 'F:\\Malware Image Based\\Dataset\\VirusShare_b4dacc1d3fa4291fbd0fc1f1000f3470', 'F:\\Malware Image Based\\Dataset\\VirusShare_b378e53bdd635fbc1f4ee1bd32591750', 'F:\\Malware Image Based\\Dataset\\VirusShare_b369e09677e4c1dfc29c70bf907a410a', 'F:\\Malware Image Based\\Dataset\\VirusShare_b329afa94f9ebf1e024ffed4af0ed94a', 'F:\\Malware Image Based\\Dataset\\VirusShare_b06b3dba459b7f9a5bd0cf3027879f92', 'F:\\Malware Image Based\\Dataset\\VirusShare_b012567ec0f4428ad38a26254aae9710', 'F:\\Malware Image Based\\Dataset\\VirusShare_adb742ef683f9d572967d9eedba98b90', 'F:\\Malware Image Based\\Dataset\\VirusShare_ac71a6453e85365bdfe9af27c5ae6854', 'F:\\Malware Image Based\\Dataset\\VirusShare_ac606da44cb0c4601296e61f9241bbf0', 'F:\\Malware Image Based\\Dataset\\VirusShare_abc10c738e5d710064286c354e83b270', 'F:\\Malware Image Based\\Dataset\\VirusShare_ab5961517b7bdb20cd392dde4b79d9b0', 'F:\\Malware Image Based\\Dataset\\VirusShare_aaf512a299ecc824d7e4c6863ead09b8', 'F:\\Malware Image Based\\Dataset\\VirusShare_aa70a913b85fecf772ba5b5fedbc79f5', 'F:\\Malware Image Based\\Dataset\\VirusShare_aa14a6caa79a65c6b6916268e09fab11', 'F:\\Malware Image Based\\Dataset\\VirusShare_a96b2a6585d1fa00a53e6d7bab9d8507', 'F:\\Malware Image Based\\Dataset\\VirusShare_a8da12b7a02ae5aad2973485c3aaf143', 'F:\\Malware Image Based\\Dataset\\VirusShare_a7eac6bb45e35e85f7307fa418525b41', 'F:\\Malware Image Based\\Dataset\\VirusShare_a7d8be09d8592f66550b1930c33eb7e0', 'F:\\Malware Image Based\\Dataset\\VirusShare_a53baa421ed89c622a9cd0ebec8fe840', 'F:\\Malware Image Based\\Dataset\\VirusShare_a4dd883109cd99595ccdf53e739f1562', 'F:\\Malware Image Based\\Dataset\\VirusShare_a4980d038676c5f695ffd5d8bfe1000e', 'F:\\Malware Image Based\\Dataset\\VirusShare_a45ed666de88393699029a4b090d9ff0', 'F:\\Malware Image Based\\Dataset\\VirusShare_a428ff04d3806d1f832535a90d75c4d1', 'F:\\Malware Image Based\\Dataset\\VirusShare_a3cb54131b2b32c37a5bc79f7828fda8', 'F:\\Malware Image Based\\Dataset\\VirusShare_a33adf94a63b4efec39f151648aa3f4e', 'F:\\Malware Image Based\\Dataset\\VirusShare_a25e01ff35080df255d7638230d639e3', 'F:\\Malware Image Based\\Dataset\\VirusShare_a006e103875d9469a6a06359f274f414', 'F:\\Malware Image Based\\Dataset\\VirusShare_9ff1b195b02e28aef09905ac7c81895b', 'F:\\Malware Image Based\\Dataset\\VirusShare_9ef05db296b09d7c5fdd74d110e67e7c', 'F:\\Malware Image Based\\Dataset\\VirusShare_9edcea0c684c457c216ae1a6c4ce34d1', 'F:\\Malware Image Based\\Dataset\\VirusShare_9ec2d1cf4bc745300a7109006ba06166', 'F:\\Malware Image Based\\Dataset\\VirusShare_9de2cbc7211ca34ec78d1ddb07240140', 'F:\\Malware Image Based\\Dataset\\VirusShare_9d946dc97ea49879fba9b00499dc3f2d', 'F:\\Malware Image Based\\Dataset\\VirusShare_9d3085bfbe6c69878f24106bcc45e9e0', 'F:\\Malware Image Based\\Dataset\\VirusShare_9c2c3fee25a8b8f3a33619c12d812350', 'F:\\Malware Image Based\\Dataset\\VirusShare_9bf28cb988a4e0d83144da99497d45d0', 'F:\\Malware Image Based\\Dataset\\VirusShare_9b387177a8721c86742a1e368c428e57', 'F:\\Malware Image Based\\Dataset\\VirusShare_9b19b506de51a208c879c1bf965d3d50', 'F:\\Malware Image Based\\Dataset\\VirusShare_9adc555f71d0a20612257f00aed8c08b', 'F:\\Malware Image Based\\Dataset\\VirusShare_9aadb8aa423efd43eb79fb21355eb46a', 'F:\\Malware Image Based\\Dataset\\VirusShare_9a8cfdb89335825c008b029042b91521', 'F:\\Malware Image Based\\Dataset\\VirusShare_996e5213871754b542b3c27551b73a7c', 'F:\\Malware Image Based\\Dataset\\VirusShare_995aa76018c10ea436bb63bf2493a0df', 'F:\\Malware Image Based\\Dataset\\VirusShare_98363ffa1b654d350684a2c5e01bd3cf', 'F:\\Malware Image Based\\Dataset\\VirusShare_98096143e04ad363597b863a5f9dd440', 'F:\\Malware Image Based\\Dataset\\VirusShare_9743d8429afa0a52b39e6235903ce7c0', 'F:\\Malware Image Based\\Dataset\\VirusShare_95b99cde995ea982e6e2748ff039df73', 'F:\\Malware Image Based\\Dataset\\VirusShare_959e072eec7c8976d2b7d0a4053b0880', 'F:\\Malware Image Based\\Dataset\\VirusShare_9545a5136a50dd3a87feda9dcad4a03c', 'F:\\Malware Image Based\\Dataset\\VirusShare_95083d51f48a39f055617136c88c00c2', 'F:\\Malware Image Based\\Dataset\\VirusShare_94eae71775db4dbd1e4a9011125ef680', 'F:\\Malware Image Based\\Dataset\\VirusShare_94c895fb801a6f421949303f272f9030', 'F:\\Malware Image Based\\Dataset\\VirusShare_945bda8e24e813d148c2a29c8856f460', 'F:\\Malware Image Based\\Dataset\\VirusShare_944c6fddd39cd6c1d8393323bc74ab43', 'F:\\Malware Image Based\\Dataset\\VirusShare_92a081b333998284c27b14c6bacc8e70', 'F:\\Malware Image Based\\Dataset\\VirusShare_91049f4112265b5f757016cf9aa4e57a', 'F:\\Malware Image Based\\Dataset\\VirusShare_909bd4d5756d49c665dd134f9f9c3459', 'F:\\Malware Image Based\\Dataset\\VirusShare_8e394d0e0a6d4bd58cff8298b1adecbf', 'F:\\Malware Image Based\\Dataset\\VirusShare_8cfbeaf6010e2985a7f069b3b7dfc9fc', 'F:\\Malware Image Based\\Dataset\\VirusShare_8b738bf4f84155d683bd2d84093a6b43', 'F:\\Malware Image Based\\Dataset\\VirusShare_8b6158f74baf89738b543f5311c30360', 'F:\\Malware Image Based\\Dataset\\VirusShare_8b1c459d43af15eb6de22e3053feef42', 'F:\\Malware Image Based\\Dataset\\VirusShare_8a97b4b9d3dcb9fa95916bf1e68be0c5', 'F:\\Malware Image Based\\Dataset\\VirusShare_8a79efa291682ed2be7c20170bb1d0a0', 'F:\\Malware Image Based\\Dataset\\VirusShare_8a45ebafe0704ca4075824288676d360', 'F:\\Malware Image Based\\Dataset\\VirusShare_89f66c8fda11eaccab31966474fdf502', 'F:\\Malware Image Based\\Dataset\\VirusShare_89c46b179dc9c6f09704e89bc305f810', 'F:\\Malware Image Based\\Dataset\\VirusShare_88eadfdeccc18740c7fff1c5dd1f4190', 'F:\\Malware Image Based\\Dataset\\VirusShare_88df386577e4275f26dd74ea5f948c91', 'F:\\Malware Image Based\\Dataset\\VirusShare_8889e9984ad2abbbf99b1a965492af9f', 'F:\\Malware Image Based\\Dataset\\VirusShare_886832c4b781fc5d17f4c00259eed34e', 'F:\\Malware Image Based\\Dataset\\VirusShare_8749a9f382ca5f860f210cd274d1aaeb', 'F:\\Malware Image Based\\Dataset\\VirusShare_870f3267560c83f3485e63635e653a80', 'F:\\Malware Image Based\\Dataset\\VirusShare_869504de21793a44b5069ac91fd12a50', 'F:\\Malware Image Based\\Dataset\\VirusShare_8529b14602b4d4afb1ebfc53eaed4e7b', 'F:\\Malware Image Based\\Dataset\\VirusShare_84f349349a993a241f85aa00dfa3a135', 'F:\\Malware Image Based\\Dataset\\VirusShare_8468a43368bff383e371c410a3776520', 'F:\\Malware Image Based\\Dataset\\VirusShare_845ce376035f6426165dc69b096fa7f3', 'F:\\Malware Image Based\\Dataset\\VirusShare_82011620c996bca3b6f4d0ab52bf35e0', 'F:\\Malware Image Based\\Dataset\\VirusShare_8179576817e6b1b2af12ded0a9699e0c', 'F:\\Malware Image Based\\Dataset\\VirusShare_814c980f50499526d9c7a9c2a29a6e00', 'F:\\Malware Image Based\\Dataset\\VirusShare_7eaacdfd6ec6abbe221a8883c5f7141e', 'F:\\Malware Image Based\\Dataset\\VirusShare_7df96a44b714c2057c09e9c7dee2046f', 'F:\\Malware Image Based\\Dataset\\VirusShare_7dcf49082b204ab60c124ca971368a80', 'F:\\Malware Image Based\\Dataset\\VirusShare_7ca19905989c867f3a1c0cc8f8d3608e', 'F:\\Malware Image Based\\Dataset\\VirusShare_7c663f8efd57ac0a1aeb2fa1f96fea90', 'F:\\Malware Image Based\\Dataset\\VirusShare_78eea9c399213eeba7c1722b03200050', 'F:\\Malware Image Based\\Dataset\\VirusShare_785e6fbc296d6899e99901542e53683e', 'F:\\Malware Image Based\\Dataset\\VirusShare_77db027e8fb7a1e3ad27311ac5b30801', 'F:\\Malware Image Based\\Dataset\\VirusShare_77959326f412fcc845e5557ce7fa3dc1', 'F:\\Malware Image Based\\Dataset\\VirusShare_75fd9bfd3e33cec83001be9258737d60', 'F:\\Malware Image Based\\Dataset\\VirusShare_75aec9ad7123d24a9a99d04ef3d684ac', 'F:\\Malware Image Based\\Dataset\\VirusShare_75227cefa898a8edd1673181a055b2a3', 'F:\\Malware Image Based\\Dataset\\VirusShare_75097439333d18aec6352e2dfb160ffd', 'F:\\Malware Image Based\\Dataset\\VirusShare_74dc84ae86f91d00f3df3d394f094e61', 'F:\\Malware Image Based\\Dataset\\VirusShare_746d7d1acc453df57976d68eb1f24dd7', 'F:\\Malware Image Based\\Dataset\\VirusShare_7450f4a4a39db38c6c1744687a0f10f0', 'F:\\Malware Image Based\\Dataset\\VirusShare_741a605d4c79ca5dd7c109bfc6329d80', 'F:\\Malware Image Based\\Dataset\\VirusShare_73ebb07d5e947f7e977f0b3ea82e877a', 'F:\\Malware Image Based\\Dataset\\VirusShare_73e751c459bc7bdf7de71243594d2876', 'F:\\Malware Image Based\\Dataset\\VirusShare_730dae4226fcc6ead620e3aff37e2c00', 'F:\\Malware Image Based\\Dataset\\VirusShare_725a89595da6eacc931f46e0b6fd05fa', 'F:\\Malware Image Based\\Dataset\\VirusShare_71d367fa05fac23ad47b7ddb12d1c08b', 'F:\\Malware Image Based\\Dataset\\VirusShare_71aac9a7c1aeea5a0ac6e422d9f48578', 'F:\\Malware Image Based\\Dataset\\VirusShare_705ec4891d86b8ce45a829f479ba61ce', 'F:\\Malware Image Based\\Dataset\\VirusShare_6f6fae7f83f849acef0aedd3fe255daf', 'F:\\Malware Image Based\\Dataset\\VirusShare_6f47665721000daa3e4e69a190dbb120', 'F:\\Malware Image Based\\Dataset\\VirusShare_6f1eb46e93a267a6e5100bb6c131987c', 'F:\\Malware Image Based\\Dataset\\VirusShare_6daa21426311e3b77e90dce80c510680', 'F:\\Malware Image Based\\Dataset\\VirusShare_6caef63482bb01dc1248cd8d5886ed2a', 'F:\\Malware Image Based\\Dataset\\VirusShare_6c8b678fe73c9c2af26242a4c13b5503', 'F:\\Malware Image Based\\Dataset\\VirusShare_6c6b9ebb2ad4824d3d9a933b67475230', 'F:\\Malware Image Based\\Dataset\\VirusShare_6b5fddea3f318ecc8c88d2c26afe4900', 'F:\\Malware Image Based\\Dataset\\VirusShare_6afc28afdabce1395db482739676c73f', 'F:\\Malware Image Based\\Dataset\\VirusShare_6a389cdab80d9eb307cddd061c5bb457', 'F:\\Malware Image Based\\Dataset\\VirusShare_692962261a2869eb08b53a0753be2270', 'F:\\Malware Image Based\\Dataset\\VirusShare_691722b719d7b064c737893fd82ce7ac', 'F:\\Malware Image Based\\Dataset\\VirusShare_69145d45bafb2ca02eb327287aedf5a0', 'F:\\Malware Image Based\\Dataset\\VirusShare_68f88043a7127b92b1d6d302e56d72b6', 'F:\\Malware Image Based\\Dataset\\VirusShare_67ca4198de8a01178c6d1aab5068f423', 'F:\\Malware Image Based\\Dataset\\VirusShare_67c3370ad93917e707dc64be8857308d', 'F:\\Malware Image Based\\Dataset\\VirusShare_67485c35828c6b17459eb72e61200c84', 'F:\\Malware Image Based\\Dataset\\VirusShare_66e650b0e4447f61dfb07c25f7b4ab10', 'F:\\Malware Image Based\\Dataset\\VirusShare_66ce6434e06453cd00d61d28636c26c5', 'F:\\Malware Image Based\\Dataset\\VirusShare_66c26110b2162918e3a126ddc2f65c76', 'F:\\Malware Image Based\\Dataset\\VirusShare_66449d8291bef66213e5ce69b5c8d7b1', 'F:\\Malware Image Based\\Dataset\\VirusShare_65ff82075607b2a67c2d2783bbced753', 'F:\\Malware Image Based\\Dataset\\VirusShare_65fd8671531fa64a8c0469ad515e8f38', 'F:\\Malware Image Based\\Dataset\\VirusShare_64c995695dca19432376634bb1d503a6', 'F:\\Malware Image Based\\Dataset\\VirusShare_643fb3ead098541e428bc474930decff', 'F:\\Malware Image Based\\Dataset\\VirusShare_63123bd350e7315cbee674eb67c84c10', 'F:\\Malware Image Based\\Dataset\\VirusShare_624298cf7c37e3e82afa03d54b915afa', 'F:\\Malware Image Based\\Dataset\\VirusShare_60f99cdad3ea54d781e8d85e09959cd0', 'F:\\Malware Image Based\\Dataset\\VirusShare_60e67ef32a0edbc7f103e8760d738eb1', 'F:\\Malware Image Based\\Dataset\\VirusShare_60a38b5c5f6fc60b932b80c6c3e26a80', 'F:\\Malware Image Based\\Dataset\\VirusShare_5fc6334c9dd8bbb67a04a17eece9df70', 'F:\\Malware Image Based\\Dataset\\VirusShare_5ef8074450b70b20a18ceb049b60be20', 'F:\\Malware Image Based\\Dataset\\VirusShare_5e0c79168ecf507985ecd5d69e2178e0', 'F:\\Malware Image Based\\Dataset\\VirusShare_5e016777992f7d4a36fa48d4c9251b60', 'F:\\Malware Image Based\\Dataset\\VirusShare_5dc340aa3397f7737684a00317e2c3a1', 'F:\\Malware Image Based\\Dataset\\VirusShare_5ccb10a8bda82c75effa82afd3f8c6a2', 'F:\\Malware Image Based\\Dataset\\VirusShare_5c520131a56fc38620caf7033de31a00', 'F:\\Malware Image Based\\Dataset\\VirusShare_5c4689f8028791f3a182fc87ef8da684', 'F:\\Malware Image Based\\Dataset\\VirusShare_5bf964c5301255b30ac660c21537ea7c', 'F:\\Malware Image Based\\Dataset\\VirusShare_5bd72e61f9c96bc71799703987a810b0', 'F:\\Malware Image Based\\Dataset\\VirusShare_5b410b291fbc7aeeb4afaccd03d858e0', 'F:\\Malware Image Based\\Dataset\\VirusShare_5aa301d6aee5f7b03123522b372f3955', 'F:\\Malware Image Based\\Dataset\\VirusShare_58e80aedea23e3a15f6f5eccab51c719', 'F:\\Malware Image Based\\Dataset\\VirusShare_5846d164c45c0125b42747ea18650020', 'F:\\Malware Image Based\\Dataset\\VirusShare_5815c3c41ef1d7945ae98840eec9b193', 'F:\\Malware Image Based\\Dataset\\VirusShare_57e12e97ded1b1b72e67826b5b169627', 'F:\\Malware Image Based\\Dataset\\VirusShare_56aca0989755c0dc7cbd07eb34d7a540', 'F:\\Malware Image Based\\Dataset\\VirusShare_56187268d695b460ca6584be0c186f68', 'F:\\Malware Image Based\\Dataset\\VirusShare_55c5efc6e2b9c377567a9cf39eecd341', 'F:\\Malware Image Based\\Dataset\\VirusShare_5578ddafb6e91aca81e2eff695f79358', 'F:\\Malware Image Based\\Dataset\\VirusShare_553becdbf768d90a71bb9088b6b423ad', 'F:\\Malware Image Based\\Dataset\\VirusShare_541446e71a06980e1df90c90097663f4', 'F:\\Malware Image Based\\Dataset\\VirusShare_52e0801f03ffad79d44736727d7fa929', 'F:\\Malware Image Based\\Dataset\\VirusShare_5064509c0cbf618d3f28d0341e2f4180', 'F:\\Malware Image Based\\Dataset\\VirusShare_4f450e8d4d432385c66d85afbf74e69d', 'F:\\Malware Image Based\\Dataset\\VirusShare_4e256f59923eadf5567831680e59b84d', 'F:\\Malware Image Based\\Dataset\\VirusShare_4da2a23f95afc83e880d2a4b28b35971', 'F:\\Malware Image Based\\Dataset\\VirusShare_4d2d3e26170e4a77ce63e246824bad92', 'F:\\Malware Image Based\\Dataset\\VirusShare_4d02b09b4a5f7b06d8ee2484de5a75c6', 'F:\\Malware Image Based\\Dataset\\VirusShare_4c827b8b3e18a5285cf89625fc6e16fd', 'F:\\Malware Image Based\\Dataset\\VirusShare_4ba0be612f302a7d6d3da1bf30669a90', 'F:\\Malware Image Based\\Dataset\\VirusShare_4b7ff45f6ef1fba477f8c97d1cc29330', 'F:\\Malware Image Based\\Dataset\\VirusShare_4b7a08b2904eb93214c3cf4c559f9b50', 'F:\\Malware Image Based\\Dataset\\VirusShare_4b580fbbc97c93235bc2d572f0335bd0', 'F:\\Malware Image Based\\Dataset\\VirusShare_4b36ea692704aaace6367a9f93f01707', 'F:\\Malware Image Based\\Dataset\\VirusShare_4a040180cfbc6e45eeb1fea12d91a6dd', 'F:\\Malware Image Based\\Dataset\\VirusShare_488363af3779abdc652d9d06467f8126', 'F:\\Malware Image Based\\Dataset\\VirusShare_486305497e03436930b8c747f215106e', 'F:\\Malware Image Based\\Dataset\\VirusShare_47f1e59d240800e0dab87934b0e1b518', 'F:\\Malware Image Based\\Dataset\\VirusShare_460cc7e225014b3b1a8365295002d5e7', 'F:\\Malware Image Based\\Dataset\\VirusShare_460730170c81114336d2432dc21029ce', 'F:\\Malware Image Based\\Dataset\\VirusShare_454792c60b73a887732a96b246476565', 'F:\\Malware Image Based\\Dataset\\VirusShare_44d835fb5c665ebefb4875d34de29519', 'F:\\Malware Image Based\\Dataset\\VirusShare_4405c43f0aa21f8824a8033c1b600966', 'F:\\Malware Image Based\\Dataset\\VirusShare_4405017afb6f12a928d2e7bc82b04a6e', 'F:\\Malware Image Based\\Dataset\\VirusShare_43196aada7501e888e8f0f1301201a50', 'F:\\Malware Image Based\\Dataset\\VirusShare_422945561c239342d6969c60df6e9cae', 'F:\\Malware Image Based\\Dataset\\VirusShare_40344a53aba2fb70886b03493f021061', 'F:\\Malware Image Based\\Dataset\\VirusShare_40325a7a5b9224a8b7bd79b59a4e0bb0', 'F:\\Malware Image Based\\Dataset\\VirusShare_3ffd42b0968fdbdc788dd5f232ad2870', 'F:\\Malware Image Based\\Dataset\\VirusShare_3fbe2234e072048cc390caefbe9aade0', 'F:\\Malware Image Based\\Dataset\\VirusShare_3f9db3c4194e89ebe90f2b2035c69490', 'F:\\Malware Image Based\\Dataset\\VirusShare_3e6725c5da6572be0f0f911087aa981d', 'F:\\Malware Image Based\\Dataset\\VirusShare_3e1c892c7adcb45c6f363ec713806c52', 'F:\\Malware Image Based\\Dataset\\VirusShare_3df68e1ea4e0ef82c0cb854ebb2541c0', 'F:\\Malware Image Based\\Dataset\\VirusShare_3db8d1f6196600491aaf824ebed98224', 'F:\\Malware Image Based\\Dataset\\VirusShare_3d9ad75b240c10af929533ce04ef566d', 'F:\\Malware Image Based\\Dataset\\VirusShare_3d846ebcaa9da0954323ca16b9871c80', 'F:\\Malware Image Based\\Dataset\\VirusShare_3d47b0b15acbf9307d1847e47703ec70', 'F:\\Malware Image Based\\Dataset\\VirusShare_3c13d3a1dfad4b318b6d98258bd55830', 'F:\\Malware Image Based\\Dataset\\VirusShare_3be5e4d9c5c12eda50273f64478695d5', 'F:\\Malware Image Based\\Dataset\\VirusShare_3b2415e11ddbbf2f1f07d9908923be29', 'F:\\Malware Image Based\\Dataset\\VirusShare_39a51883590ea89e6500dc9632088368', 'F:\\Malware Image Based\\Dataset\\VirusShare_3841ebf0815f2e3a250b9c6607a7bf82', 'F:\\Malware Image Based\\Dataset\\VirusShare_377668c00b6ae77db79916efd3d1847f', 'F:\\Malware Image Based\\Dataset\\VirusShare_3642707a99e5e40bed8679c6c79476cd', 'F:\\Malware Image Based\\Dataset\\VirusShare_3515da70841df3360f16e9fbb6a1ad01', 'F:\\Malware Image Based\\Dataset\\VirusShare_33e3e69c56b45e2d00aa8f3182fea8e0', 'F:\\Malware Image Based\\Dataset\\VirusShare_33a56105443ae5f61feab26a1c0e9094', 'F:\\Malware Image Based\\Dataset\\VirusShare_331384d09284694fd1b0b507fc6cb507', 'F:\\Malware Image Based\\Dataset\\VirusShare_3148c8643fd6e948ede0b0e2a11a64e0', 'F:\\Malware Image Based\\Dataset\\VirusShare_31417d989c4e562386aa204894f3b5b0', 'F:\\Malware Image Based\\Dataset\\VirusShare_3121644912316966125da6a2fe34d3a3', 'F:\\Malware Image Based\\Dataset\\VirusShare_2f06d1a30435c8a2d91a2b239de224c0', 'F:\\Malware Image Based\\Dataset\\VirusShare_2eee5674812a17cfcbef198ca9baa840', 'F:\\Malware Image Based\\Dataset\\VirusShare_2e1bb99f1a46fcdb7d2d8795bcb42a70', 'F:\\Malware Image Based\\Dataset\\VirusShare_2deecbe7a31573d753d42e231e002d6e', 'F:\\Malware Image Based\\Dataset\\VirusShare_2cfaa7ad32a067efd1036ade9e8b7eae', 'F:\\Malware Image Based\\Dataset\\VirusShare_2c8e82342b05e58049ddd499cb3fb58d', 'F:\\Malware Image Based\\Dataset\\VirusShare_2bf17470d8fbe53f19be2e57ab39baa0', 'F:\\Malware Image Based\\Dataset\\VirusShare_2a64c1e4f13840532a2a300349a59c16', 'F:\\Malware Image Based\\Dataset\\VirusShare_2a481ee27236670815aefafe192254b0', 'F:\\Malware Image Based\\Dataset\\VirusShare_29cfede79fab094a3d74c390f411c4fc', 'F:\\Malware Image Based\\Dataset\\VirusShare_27da691faec84c45f42e8b6eff48d91c', 'F:\\Malware Image Based\\Dataset\\VirusShare_27be94866fcee3dbf7ef9a4900faebd1', 'F:\\Malware Image Based\\Dataset\\VirusShare_261e10778729e34b5746d1bc63655e58', 'F:\\Malware Image Based\\Dataset\\VirusShare_25501bfa189c26839cbf7865eb6d16d6', 'F:\\Malware Image Based\\Dataset\\VirusShare_245756e796db752feb0db7a12866f010', 'F:\\Malware Image Based\\Dataset\\VirusShare_23a72bb989e9691e605c06ed6db4d027', 'F:\\Malware Image Based\\Dataset\\VirusShare_235468fde428dadc99a11ea21ef32d5a', 'F:\\Malware Image Based\\Dataset\\VirusShare_221351fed9e0758a87856ecf46f0f294', 'F:\\Malware Image Based\\Dataset\\VirusShare_212076c5b039a89e5e93d9f110bc078b', 'F:\\Malware Image Based\\Dataset\\VirusShare_1fe9363001a54717f6a4ee65a1b8dfbc', 'F:\\Malware Image Based\\Dataset\\VirusShare_1f667e6c918dded882accd26e0c5dd47', 'F:\\Malware Image Based\\Dataset\\VirusShare_1f48fd13a2196f98382263eba84f2153', 'F:\\Malware Image Based\\Dataset\\VirusShare_1f11a6bf7ff728c5b2d64912fde62f62', 'F:\\Malware Image Based\\Dataset\\VirusShare_1ebb133a2ccdd5700f07740143b0f220', 'F:\\Malware Image Based\\Dataset\\VirusShare_1eb54927f5ab278d9cc197443cbe8e05', 'F:\\Malware Image Based\\Dataset\\VirusShare_1defafbb88ff5efd622a188e4968f339', 'F:\\Malware Image Based\\Dataset\\VirusShare_1dab6ea75558b4fda798c43cfb3e1610', 'F:\\Malware Image Based\\Dataset\\VirusShare_1d9afa8a7970af28631bd71f73488b1d', 'F:\\Malware Image Based\\Dataset\\VirusShare_1be075f960f739c4ca5112e0b14ce7da', 'F:\\Malware Image Based\\Dataset\\VirusShare_1b81bea3ded7ec7216048de4ec84fca9', 'F:\\Malware Image Based\\Dataset\\VirusShare_1b266f23cab5ae881ca35344e86c3ef0', 'F:\\Malware Image Based\\Dataset\\VirusShare_1af87ca8b6141d34ad5fdf85644edec3', 'F:\\Malware Image Based\\Dataset\\VirusShare_1abc7ec5dd730d3fe7a95d887f6a5440', 'F:\\Malware Image Based\\Dataset\\VirusShare_1a9564242f62ea2c54ae490a9bcda2d6', 'F:\\Malware Image Based\\Dataset\\VirusShare_1a805df9811e1033e3f358489a71006f', 'F:\\Malware Image Based\\Dataset\\VirusShare_19e7f4b57dcffd8b555aa1d9a67182c2', 'F:\\Malware Image Based\\Dataset\\VirusShare_188973635b66c1272589de506bfea7c0', 'F:\\Malware Image Based\\Dataset\\VirusShare_180f37b1ff8268ac2b95beee6989aba2', 'F:\\Malware Image Based\\Dataset\\VirusShare_17fa4a03b9411c2413988b7acdca4cd3', 'F:\\Malware Image Based\\Dataset\\VirusShare_16790cede0fcb3329af7ba2bc2fbce30', 'F:\\Malware Image Based\\Dataset\\VirusShare_155ffbe8c4eb69a812f8fe8c802df000', 'F:\\Malware Image Based\\Dataset\\VirusShare_14a4e9a70d1c5540bcd41e611dc58ab0', 'F:\\Malware Image Based\\Dataset\\VirusShare_1408711a0c498c6233c59d9c6419e095', 'F:\\Malware Image Based\\Dataset\\VirusShare_12e49584f18cd67b2a657f8301106503', 'F:\\Malware Image Based\\Dataset\\VirusShare_11822b59d2e87064c1691c6dab6ef8c7', 'F:\\Malware Image Based\\Dataset\\VirusShare_10fec79af25b419a0845eae1438314cf', 'F:\\Malware Image Based\\Dataset\\VirusShare_10a1f49a58e55ed7c53439e0c5973103', 'F:\\Malware Image Based\\Dataset\\VirusShare_109027a9d2a7bf23e3c5f71993eb2a88', 'F:\\Malware Image Based\\Dataset\\VirusShare_101e33a3cf8d05db851de1323c9b60ae', 'F:\\Malware Image Based\\Dataset\\VirusShare_0f55017cace39dd67995fd5e89a61805', 'F:\\Malware Image Based\\Dataset\\VirusShare_0d9aa42bb32226b412d8ae64aa71a26c', 'F:\\Malware Image Based\\Dataset\\VirusShare_0d526307aba138e54912087c15a50c13', 'F:\\Malware Image Based\\Dataset\\VirusShare_0d40257f2abd6635b093c6d4fc119cbb', 'F:\\Malware Image Based\\Dataset\\VirusShare_0d114f0c19eb67cb7b0665ad4ae79f2c', 'F:\\Malware Image Based\\Dataset\\VirusShare_0cb2623b1d909885bae972fcde9478ca', 'F:\\Malware Image Based\\Dataset\\VirusShare_0c9b818edbae356e1a736f8b6270e0cf', 'F:\\Malware Image Based\\Dataset\\VirusShare_0c668ae2d0bf8a27255fe2b4a3020d9b', 'F:\\Malware Image Based\\Dataset\\VirusShare_0c1bfa1d3a4519e660db997ef8d75578', 'F:\\Malware Image Based\\Dataset\\VirusShare_0b6326745e516532f8e59e730972ddf5', 'F:\\Malware Image Based\\Dataset\\VirusShare_0b05b40ca14e32b8e4944bdd193716d3', 'F:\\Malware Image Based\\Dataset\\VirusShare_09de47087fc7c2813b363e58f85e08f5', 'F:\\Malware Image Based\\Dataset\\VirusShare_08de483897f1387a724af0ca066684d6', 'F:\\Malware Image Based\\Dataset\\VirusShare_07dd93a604bbf96ee3814bf97d8fafba', 'F:\\Malware Image Based\\Dataset\\VirusShare_0765d6091a37d448a1a9be7505e1a321', 'F:\\Malware Image Based\\Dataset\\VirusShare_0762d54455c36b9dadbb58145e80184e', 'F:\\Malware Image Based\\Dataset\\VirusShare_064765fe0a5cdacd54b4a5cdd3cdc161', 'F:\\Malware Image Based\\Dataset\\VirusShare_541e1f7d6a3737595d112d2bf88e9c30']
#
#     # count = 0
#     #
#     # ransom_link_dic = ransom_label.create_dic_ransom_dic()
#     # ransom_class = ransom_label.read_ransom_name()
#
#     # for key in ransom_class:
#     #     name = key
#     #     links = ransom_link_dic[key]
#     #     for link in links:
#     #         if isinstance(link, list):
#     #             for thing in link:
#     #                 if valid_size(get_size(len(getBinaryData(thing)))):
#     #                     file_queue.append(thing)
#     #                     # print(file_queue)
#     #                     print(name, thing, type(thing))
#     #         else:
#     #             if valid_size(get_size(len(getBinaryData(link)))):
#     #                 file_queue.append(link)
#     #                 print(name, type(link), link)
#     # print(file_queue)
#
#     other_virus = ransom_label.create_other_virus_dic()
#     count = 0
#     for key in other_virus:
#         name = key
#         links = other_virus[key]
#         for link in links:
#             if isinstance(link, list):
#                 for thing in link:
#                     # if valid_size(get_size(len(getBinaryData(thing)))):
#                     fix_link = 'E' + thing[1:]
#                     count+=1
#                     file_queue.append(fix_link)
#                     print(name, fix_link, type(thing))
#             else:
#                 # if valid_size(get_size(len(getBinaryData(link)))):
#                 fix_link = 'E' + link[1:]
#                 count += 1
#                 file_queue.append(fix_link)
#                 print(name, type(fix_link), fix_link)
#
#         if count > 1300:
#             break
#     print(count)
#
#     # count =0
#     # for root, directories, files in os.walk(input_dir):
#     #
#     #     for filename in files:
#     #         if ".dll" in filename:
#     #
#     #             file_path = os.path.join(root, filename)
#     #             if valid_size(get_size(len(getBinaryData(file_path)))):
#     #                 count+=1
#     #                 file_queue.append(file_path)
#     #                 print(file_path)
#     #             if count == 4000:
#     #                 break
#     #     if count == 4000:
#     #         break
#     # print(count)
#     #
#
#     # count = 0
#     # for root, directories, files in os.walk(input_dir):
#     #
#     #     for filename in files:
#     #
#     #         file_path = os.path.join(root, filename)
#     #
#     #         # print(os.path.basename(root))
#     #
#     #         # if not valid_size(get_size(Path(file_path).stat().st_size, width)):
#     #         #     # print(file_path, "not valid")
#     #         #     continue
#     #
#     #         count += 1
#     #
#     #         file_queue.append((os.path.basename(root), file_path))
#     #         # print(count, filename)
#
#     # for _class, ffile in file_queue:
#     for ffile in file_queue:
#         print(ffile)
#         k = k + 1
#         print("%d.Ten file: %s" % (k, ffile))
#         try:
#             results = extract_infos(ffile)
#             results.append(2)
#             ff.write(csv_delimiter.join(map(lambda x: str(x), results)) + "\n")
#         except pefile.PEFormatError:
#             print('\t -> Bad PE format')
#
#
#
#     # for ffile in os.listdir('Malicious'):
#     #     k = k + 1
#     #     print("%d.Ten file: %s" % (k, ffile))
#     #     try:
#     #         results = extract_infos(os.path.join('Malicious/', ffile))
#     #         results.append(0)
#     #         ff.write(csv_delimiter.join(map(lambda x: str(x), results)) + "\n")
#     #     except pefile.PEFormatError as e:
#     #         print('\t -> Bad PE format')
#     print("Done!")
#     ff.close()
