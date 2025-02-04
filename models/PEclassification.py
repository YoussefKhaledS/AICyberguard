import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
from PIL import Image
import pefile
import binascii

# Load the trained model
model = load_model('C:\\Users\\youssef khaled\\Desktop\\GP\\code\\models\\saved\\malware_model.h5')

# Classification index
class_index = {
    'Adialer.C': 0,
    'Agent.FYI': 1,
    'Allaple.A': 2,
    'Allaple.L': 3,
    'Alueron.gen!J': 4,
    'Autorun.K': 5,
    'Benign': 6,
    'C2LOP.P': 7,
    'C2LOP.gen!g': 8,
    'Dialplatform.B': 9,
    'Dontovo.A': 10,
    'Fakerean': 11,
    'Instantaccess': 12,
    'Lolyda.AA1': 13,
    'Lolyda.AA2': 14,
    'Lolyda.AA3': 15,
    'Lolyda.AT': 16,
    'Malex.gen!J': 17,
    'Obfuscator.AD': 18,
    'Rbot!gen': 19,
    'Skintrim.N': 20,
    'Swizzor.gen!E': 21,
    'Swizzor.gen!I': 22,
    'VB.AT': 23,
    'Wintrim.BX': 24,
    'Yuner.A': 25
}

# Reverse the class index for label lookup
index_to_class = {v: k for k, v in class_index.items()}

# Functions from the PE_to_img.ipynb file


def pe2hex(file_path):
    pe = pefile.PE(file_path)
    hex_data = b''
    for section in pe.sections:
        hex_data += section.get_data()
    return binascii.hexlify(hex_data).decode('utf-8')


def hex2img(hex_string, img_size=(256, 256)):
    byte_data = bytes.fromhex(hex_string)
    img = np.frombuffer(byte_data, dtype=np.uint8)

    expected_size = img_size[0] * img_size[1] * 3
    if img.size < expected_size:
        # Pad with zeros if the image size is smaller than expected
        padding = expected_size - img.size
        img = np.pad(img, (0, padding), mode='constant', constant_values=0)
    elif img.size > expected_size:
        # Trim excess data if the image size is larger than expected
        img = img[:expected_size]

    img = img.reshape((img_size[0], img_size[1], 3))
    return Image.fromarray(img, 'RGB')

# Function to classify a single PE file


def classify_pe_file(file_path):
    try:
        # Convert the PE file to a hexadecimal string
        hex_string = pe2hex(file_path)

        # Convert the hex string to an image
        img = hex2img(hex_string)

        # Preprocess the image
        # Ensure it matches the input size of the model
        img = img.resize((256, 256))
        img_array = np.array(img) / 255.0  # Normalize the image
        img_array = np.expand_dims(img_array, axis=0)  # Add batch dimension

        # Classify the image
        prediction = model.predict(img_array)
        predicted_class_index = np.argmax(prediction, axis=1)[0]
        class_label = index_to_class.get(predicted_class_index, 'Unknown')
        confidence = prediction[0][predicted_class_index]

        return {
            'file_path': file_path,
            'classification': class_label,
            'confidence': confidence
        }

    except Exception as e:
        return {'error': str(e)}

# Example usage
result = classify_pe_file('C:\\Users\\youssef khaled\\Desktop\\GP\\dataSets\\DikeDataset\\benign\\iosifache DikeDataset main files-benign\\0a8deb24eef193e13c691190758c349776eab1cd65fba7b5dae77c7ee9fcc906.exe')
print(result)
