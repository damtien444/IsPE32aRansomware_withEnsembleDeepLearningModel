import argparse
import os
import warnings

import torch
import torch.backends.cudnn as cudnn
import torch.nn as nn
import torch.optim as optim
import yaml
from munch import Munch
from torch.autograd import Variable

import wandb
from dataloader.image_loader import get_loader
from model.net import get_model
from utils.plot import plot_acc, plot_loss

warnings.filterwarnings("ignore")


def make_dir_if_not_exist(path):
    if not os.path.exists(path):
        os.makedirs(path)


class AverageMeter(object):
    """Computes and stores the average and current value"""

    def __init__(self):
        self.reset()

    def reset(self):
        self.val = 0
        self.avg = 0
        self.sumval = 0
        self.count = 0

    def update(self, val, n=1):
        self.val = val
        self.sumval += val * n
        self.count += n
        self.avg = self.sumval / self.count


def main():
    torch.manual_seed(1)
    if args.cuda:
        torch.cuda.manual_seed(1)
    cudnn.benchmark = True

    exp_dir = os.path.join(args.result_dir, args.exp_name)
    make_dir_if_not_exist(exp_dir)

    # Build Model
    model = get_model(args, device)

    wandb.init(project="5_features_imcec", entity="damtien440")

    if model is None:
        print('No model!')
        return

    # Criterion and Optimizer
    params = []
    for key, value in dict(model.named_parameters()).items():
        if value.requires_grad:
            params += [{'params': [value]}]
    print(f'Total parameters => {sum([p.data.nelement() for p in model.parameters()])}')

    # imbalance datasets
    criterion = nn.CrossEntropyLoss().cuda() if args.cuda else nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=args.lr)

    wandb.watch(model, criterion, log="all")
    # Train Test Loop
    train_data_loader, test_data_loader, labels_class = get_loader(args)
    total_loss_train, total_loss_test = [], []
    total_acc_train, total_acc_test = [], []
    best_loss = 100

    for epoch in range(1, args.epochs + 1):
        # Init data loaders
        # Test train
        loss_test = test(labels_class, test_data_loader, model, criterion, epoch, total_acc_test, total_loss_test)
        train(train_data_loader, model, criterion, optimizer, epoch, total_acc_train, total_loss_train)

        is_best = loss_test < best_loss
        if is_best:
            # Save model
            model_to_save = {
                'state_dict': model.state_dict(),
            }
            if epoch % args.ckp_freq == 0:
                file_name = os.path.join(exp_dir, "best.pt")
                save_checkpoint(model_to_save, file_name)
            best_loss = loss_test
    draw_ROC_ConfusionMatrix_PE(model, test_data_loader, labels_class)
    plot_acc(exp_dir, total_acc_train, total_acc_test)
    plot_loss(exp_dir, total_loss_train, total_loss_test)


def train(data, model, criterion, optimizer, epoch, total_acc_train, total_loss_train):
    print("******** Training ********")
    losses_all_train = AverageMeter()
    accs = 0
    model.train()
    for batch_idx, datasets in enumerate(data):
        images, labels = datasets

        images = Variable(images.to(device))
        labels = Variable(labels.to(device))

        embed_feat = model(images)
        loss = criterion(embed_feat, labels)

        _, preds = torch.max(embed_feat.data, 1)
        acc = torch.sum(preds == labels.data)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        losses_all_train.update(loss)
        accs += acc / labels.shape[0]

    total_loss_train.append(losses_all_train.avg)
    total_acc_train.append(100 * accs / len(data))
    wandb.log({"loss_train": losses_all_train.avg})
    wandb.log({"acc_train": 100 * accs / len(data)})
    print('Train Epoch: {}\t'
          'Loss: {:.4f} \t'
          'Acc: {:.2f}% \t'.format(
        epoch, losses_all_train.avg, 100 * accs / len(data)))


def test(labels_class, data, model, criterion, epoch, total_acc_test, total_loss_test):
    print("******** Testing ********")
    losses_all_test = AverageMeter()
    accs = 0
    with torch.no_grad():
        model.eval()
        for batch_idx, datasets in enumerate(data):
            images, labels = datasets

            images = Variable(images.to(device))
            labels = Variable(labels.to(device))

            embed_feat = model(images)
            loss = criterion(embed_feat, labels)

            _, preds = torch.max(embed_feat.data, 1)
            acc = torch.sum(preds == labels.data)
            losses_all_test.update(loss)
            accs += acc / labels.shape[0]

        print('Test set: \tLoss: {:.4f}, \tAcc: {:.2f}%'.format(
            losses_all_test.avg, 100 * accs / len(data)))

        total_loss_test.append(losses_all_test.avg)
        total_acc_test.append(100 * accs / len(data))
        wandb.log({"loss_test": losses_all_test.avg})
        wandb.log({"acc_test": 100 * accs / len(data)})
        return losses_all_test.avg


def save_checkpoint(state, file_name):
    torch.save(state, file_name)

def draw_ROC_ConfusionMatrix_PE(model, test_data_loader, labels_class):
    list_embed_vector = torch.tensor([])
    list_labels = torch.tensor([])

    with torch.no_grad():
        model.eval()
        for batch_idx, datasets in enumerate(test_data_loader):
            images, labels = datasets

            images = Variable(images.to(device))
            labels = Variable(labels.to(device))
            embed_feat = model(images)
            if batch_idx == 0:
                list_embed_vector = embed_feat
                list_labels = labels
            else:
                list_embed_vector = torch.cat((list_embed_vector, embed_feat), dim=0)
                list_labels = torch.cat((list_labels, labels), dim=0)
        preds = torch.argmax(list_embed_vector, dim=1)
        if(args.cuda):
            wandb.log({"ROC_test": wandb.plot.roc_curve(list_labels.data.cpu(), list_embed_vector.data.cpu(), labels=labels_class),
                       "PR_test": wandb.plot.pr_curve(list_labels.data.cpu(), list_embed_vector.data.cpu(), labels=labels_class,
                                                      classes_to_plot=None),
                       "Conf_mat": wandb.plot.confusion_matrix(probs=None, y_true=list_labels.data.cpu().detach().numpy(),
                                                           preds=preds.cpu().detach().numpy(),
                                                           class_names=labels_class)})
        else:
            wandb.log(
                {"ROC_test": wandb.plot.roc_curve(list_labels.data, list_embed_vector.data, labels=labels_class),
                 "PR_test": wandb.plot.pr_curve(list_labels.data, list_embed_vector.data, labels=labels_class,
                                                classes_to_plot=None),
                 "Conf_mat": wandb.plot.confusion_matrix(probs=None, y_true=list_labels.data.detach().numpy(),
                                                         preds=preds.detach().numpy(),
                                                         class_names=labels_class)})

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PyTorch Siamese Example')
    parser.add_argument('--config', default='config/myconfig.yaml', type=str, help='path to yaml config file')
    parser.add_argument('--cuda', action='store_true', default=True, help='enables CUDA training')
    global args, device, model

    args = parser.parse_args()
    args.cuda = args.cuda and torch.cuda.is_available()
    device = 'cuda' if args.cuda else 'cpu'
    with open(args.config) as f:
        params = yaml.full_load(f)
    args = Munch(params)

    main()