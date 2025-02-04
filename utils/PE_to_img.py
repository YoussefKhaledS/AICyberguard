import sys
import os
from math import log
import numpy as np
import scipy as sp
from PIL import Image
import matplotlib.pyplot as plt
import pandas as pd

pe_data_path = "../DikeDataset/benign/iosifache DikeDataset main files-benign"
bytes_data_path = "../hex_files"
img_data_path = "../benign_data/benign_imgs"
csv_data_path = "../benign_data"


def pe2hex(file_path, output_file_path):
    print('Processing ' + file_path)
    file = bytearray(open(file_path, 'rb').read())
    key = "\0"

    with open(output_file_path, 'w') as output:
        for count, byte in enumerate(file, 1):
            output.write(
                f'{byte ^ ord(key[(count - 1) % len(key)]):#0{4}x}' +
                ('\n' if not count % 16 else ' ')
            )


def pe2hex(input_file_path, output_file_path, key="\0"):
    print(f'Processing {input_file_path}...')
    with open(input_file_path, 'rb') as infile:
        file_bytes = bytearray(infile.read())
    key_length = len(key)

    with open(output_file_path, 'w') as outfile:
        for index, byte in enumerate(file_bytes, 1):
            xor_result = byte ^ ord(key[(index - 1) % key_length])
            hex_value = f'{xor_result:#04x}'
            separator = '\n' if index % 16 == 0 else ' '
            outfile.write(hex_value + separator)

    print(f'Hex conversion completed. Output written to {output_file_path}.')


files = os.listdir(pe_data_path)

for counter, name in enumerate(files):
    name_output = name.split(".")[0]
    print(name_output)
    pe2hex(os.path.join(pe_data_path, name), os.path.join(
        bytes_data_path, name_output + ".bytes"))


def hex2img(array, output_img_path):
    if array.shape[1] != 16:
        assert (False)
    b = int((array.shape[0] * 16) ** 0.5)
    b = 2 ** (int(log(b) / log(2)) + 1)
    a = int(array.shape[0] * 16 / b)
    print(a, b, array.shape)
    array = array[:a * b // 16, :]
    array = np.reshape(array, (a, b))
    im = Image.fromarray(np.uint8(array))
    im.save(output_img_path, "PNG")
    return im


files = os.listdir(bytes_data_path)

df_benign = pd.DataFrame(columns=["img_code", "target"])
benign_class_index = 25

for counter, name in enumerate(files):
    name_output = name.split(".")[0]
    output_image_path = os.path.join(img_data_path, name_output + ".png")

    print('Processing ' + output_image_path)

    with open(os.path.join(bytes_data_path, name), 'r') as f:
        array = []
        for line in f:
            xx = line.replace("\n", "").split(" ")
            if len(xx) != 16 or "" in xx:
                continue
            array.append([int(i, 16) if i != '??' else 0 for i in xx])
        img = hex2img(np.array(array), output_image_path)
        df_benign.loc[len(df_benign.index)] = [
            output_image_path, benign_class_index]

df_benign.to_csv("../benign_data/data.csv", index=False)
