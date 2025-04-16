import time
import json
import os
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

# %% image approach


def pe2hex(file_path):
    with open(file_path, 'rb') as f:
        raw_bytes = f.read()
    return binascii.hexlify(raw_bytes).decode('utf-8')


def hex2img(hex_string, img_size=(256, 256)):
    # Convert hex string to bytes
    byte_data = bytes.fromhex(hex_string)

    # Convert to numpy array of uint8
    img = np.frombuffer(byte_data, dtype=np.uint8)

    # Calculate expected size: height * width * 1 (grayscale)
    expected_size = img_size[0] * img_size[1]

    # Pad or trim to match the expected grayscale size
    if img.size < expected_size:
        padding = expected_size - img.size
        img = np.pad(img, (0, padding), mode='constant', constant_values=0)
    elif img.size > expected_size:
        img = img[:expected_size]

    # Reshape to 2D grayscale image
    img = img.reshape((img_size[0], img_size[1]))

    # Convert to RGB by stacking grayscale 3 times
    img_rgb = np.stack((img,) * 3, axis=-1)  # Shape: (256, 256, 3)

    return Image.fromarray(img_rgb, 'RGB')

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
        img.show()

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


# %% secuential approach
# Load the saved model


def classify_image_file(img_path):
    try:
        # Load and preprocess the image
        img = Image.open(img_path).convert('RGB')
        img = img.resize((256, 256))
        img_array = np.array(img) / 255.0
        img_array = np.expand_dims(img_array, axis=0)

        # Predict using the trained model
        prediction = model.predict(img_array)
        predicted_class_index = np.argmax(prediction, axis=1)[0]
        class_label = index_to_class.get(predicted_class_index, 'Unknown')
        confidence = prediction[0][predicted_class_index]

        return {
            'image_path': img_path,
            'classification': class_label,
            'confidence': confidence
        }

    except Exception as e:
        return {'error': str(e)}


# result = classify_image_file("C:\\Users\\youssef khaled\\Desktop\\GP\\dataSets\\malimg_dataset\\test\\Adialer.C\\06dec815e8fc323f9b0ec2e49d55ba4f.png")
# print(result)
