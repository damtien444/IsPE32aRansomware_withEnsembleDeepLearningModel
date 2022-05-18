import argparse
import glob
import time

import torch

from model.basemodel import IMCEC, ViTranformer
from utils.preprocessing import read_image


def load_std(path, device):
    from collections import OrderedDict
    checkpoint = torch.load(path, map_location=device)
    new_state_dict = OrderedDict()
    for k, v in checkpoint['state_dict'].items():
        name = k.replace('model.', '')
        new_state_dict[name] = v
    return new_state_dict


def predict(args, device):
    # new_state_dict = load_std(args.weight_dir, device)

    model = ViTranformer(num_classes=2)
    checkpoint = torch.load(args.weight_dir, map_location=device)
    model.load_state_dict(checkpoint['state_dict'])
    model.to(device)
    model.eval()
    acc = 0
    label = 0
    for image_path in glob.glob(args.test_dir + "*"):
        image = read_image(image_path, device)
        image = image.unsqueeze(0)
        embed_feat = model(image)
        _, pred = torch.max(embed_feat.data, 1)
        if (pred == label):
            acc += 1

    print(f'Acc: {100 * acc / len(glob.glob(args.test_dir + "*"))}%')


def predict_single_file(weight_dir, image_path, cuda):


    cuda = cuda and torch.cuda.is_available()

    if cuda:
        device = torch.device('cuda')
    else:
        device = torch.device('cpu')

    model = IMCEC(num_classes=2)
    checkpoint = torch.load(weight_dir, map_location=device)
    model.load_state_dict(checkpoint['state_dict'])
    model.to(device)
    model.eval()
    acc = 0
    label = 0
    image = read_image(image_path, device)
    image = image.unsqueeze(0)
    embed_feat = model(image)
    confidence, pred = torch.max(embed_feat.data, 1)

    return confidence.item(), pred.item()



if __name__ == '__main__':

    start = time.time()

    parser = argparse.ArgumentParser(description='PyTorch Siamese Example')
    parser.add_argument('--weight_dir',
                        default=r'E:\Malware Image Based\drive-download-20220515T075039Z-001\result\exp\best.pt',
                        type=str, help='Weight results model')
    parser.add_argument('--image_path',
                        default=r"E:\Malware Image Based\VirusShare_0a0a3312bb6916597c63ac3cc9e52564.png", type=str,
                        help='Test image')
    parser.add_argument('--num_class', default=2, type=int, help='number of class')
    parser.add_argument('--cuda', action='store_true', default=False, help='enables CUDA training')

    weight_dir = r'E:\Malware Image Based\drive-download-20220515T075039Z-001\result\exp\best.pt'
    image_path = r"E:\Malware Image Based\VirusShare_0a0a3312bb6916597c63ac3cc9e52564.png"

    global args, device
    args = parser.parse_args()
    args.cuda = args.cuda and torch.cuda.is_available()

    if args.cuda:
        device = torch.device('cuda')
    else:
        device = torch.device('cpu')

    print(predict_single_file(weight_dir, image_path, device))
    print("predict time: ", time.time() - start)
