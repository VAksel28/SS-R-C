from PIL import Image
import math
from pathlib import Path
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long
import colorsys
from Crypto.Protocol.SecretSharing import Shamir

IMAGE_PATH = '/Users/vaksenov001/Downloads/6_1_test.png'
KEY_FILENAME = './private_key.der'
SAVE_PATH = './stego_image'
SECRET = 'secret'
FORMAT = '.png' # always use png format


def shamir_split_secret(secret: str, required_shares: int,
                        distributed_shares: int):
    # encode to a 16 byte string
    secret = pad(secret.encode("utf-8"), 16) #
    return Shamir.split(k=required_shares, n=distributed_shares, secret=secret)



def shamir_recover_shares(shares: list):
    return unpad(Shamir.combine(shares), 16).decode("utf-8")


def get_all_shares_len(shares: list):
    '''
    shares: set of shares
    return sum of all shares len
    '''
    return sum([len(share[1]) for share in shares])


def get_w(image_size: tuple, shares_len: int):
    '''
    h: height of image
    w: width of image
    return w
    '''
    return image_size[0] * image_size[1] // shares_len


def get_cols_rows(num_shares: int):
    '''
    num_shares: number of shares
    return cols, rows
    '''
    cols = math.ceil(num_shares ** 2)
    rows = math.ceil(num_shares / cols)
    return cols, rows


def get_block_size(image_size: tuple, cols: int, rows: int):
    '''
    image_size: size of image
    cols: number of cols
    rows: number of rows
    shares_len: sum of all shares len
    return block_size
    '''
    return image_size[0] // cols, image_size[1] // rows


def generate_rsa_key():
    '''
    return RSA key
    '''
    random_generator = Random.new().read
    key = RSA.generate(1024, random_generator)
    # предупреждение что ключ был сгенерирован
    print('key was generated')
    return key

def save_rsa_key(key: RSA, filename: str):
    '''
    key: RSA key
    filename: filename
    '''
    der_encoded = key.export_key()

    with open(filename, 'wb') as f:
        f.write(der_encoded)


def load_rsa_key(filename: str):
    '''
    filename: filename
    return RSA key
    '''
    # check if file exists

    if not Path(filename).exists():
        key = generate_rsa_key()
        save_rsa_key(key, filename)
    else:
        with open(filename, 'rb') as f:
            key = RSA.import_key(f.read())
        if not key.has_private():
            key = generate_rsa_key()
            save_rsa_key(key, filename)
    return key


def encrypt_num_cols_rsa(num_cols: int, key: RSA):
    '''
    num_cols: number of cols
    key: RSA key
    return encrypted num_cols
    '''
    publickey = key.publickey()
    encryptor = PKCS1_OAEP.new(publickey)
    encrypted = encryptor.encrypt(long_to_bytes(num_cols))
    return encrypted


def decrypt_num_cols_rsa(encrypted: bytes, key: RSA):
    '''
    encrypted: encrypted num_cols
    key: RSA key
    return decrypted num_cols
    '''
    decryptor = PKCS1_OAEP.new(key)
    decrypted = decryptor.decrypt(encrypted)
    return bytes_to_long(decrypted)





def split_image_to_blocks(image: Image, cols: int, rows: int):
    '''
    image: image
    cols: number of cols
    rows: number of rows
    return list of blocks
    '''
    image_size = image.size
    block_size = get_block_size(image_size, cols, rows)
    blocks = []
    for i in range(cols):
        for j in range(rows):
            blocks.append(image.crop((i * block_size[0], j * block_size[1],
                                      (i + 1) * block_size[0], (j + 1) * block_size[1])))
    return blocks



def merge_blocks_to_image(blocks: list, cols: int, rows: int):
    '''
    blocks: list of blocks
    cols: number of cols
    rows: number of rows
    return image
    '''
    image_size = (blocks[0].size[0] * cols, blocks[0].size[1] * rows)
    image = Image.new('RGB', image_size)
    start_point = (0,0)
    for i in range(cols):
        for j in range(rows):
            image.paste(blocks[i * rows + j], start_point)
            start_point = (start_point[0] + blocks[i * rows + j].size[0], start_point[1])
    return image

def embed_share_to_block(block: Image, share: str):
    '''
    block: block
    shares: set of shares
    return block with embedded shares
    '''
    # embed share to block
    number = share[0]
    secret = str(bytes_to_long(share[1]))
    secret_len = len(secret)
    # split secret to bytes
    block = block.convert('RGB')
    pixels = list(block.getdata())
    # for each pixel in block
    # embed first 3 bytes of share to pixel
    # and delete first 3 bytes of share
    for i, pixel in enumerate(pixels):
        if len(secret) == 0:
            break
        r, g, b = pixel
        h, s, v = colorsys.rgb_to_hsv(r, g, b)
        # secret is bytes string
        if i == 0:
            v = secret_len
        elif i == 1:
            v = int(number)
        else:
            v = int(secret[0])
            secret = secret[1:]
        r, g, b = colorsys.hsv_to_rgb(h, s, v)
        pixels[i] = (int(r), int(g), int(b))
    block.putdata(pixels)
    return block


def extract_share_from_block(block: Image):
    '''
    block: block
    return extracted share
    '''
    # extract share from block
    pixels = list(block.getdata())
    share = ''
    r,g,b = pixels[0]
    h,s,v = colorsys.rgb_to_hsv(r, g, b)
    share_len = int(v)

    r,g,b = pixels[1]
    h,s,v = colorsys.rgb_to_hsv(r, g, b)
    share_num = int(v)
    for i in range(2,share_len+2):
        r, g, b = pixels[i]
        h, s, v = colorsys.rgb_to_hsv(r, g, b)
        share += str(v)
    return share_num, share

def embed_shares_to_blocks(blocks: list, shares: list):
    '''
    blocks: list of blocks
    shares: set of shares
    return blocks with embedded shares
    '''
    for i in range(0, len(blocks)):
        blocks[i] = embed_share_to_block(blocks[i], shares[i % len(shares)])
    return blocks

def stego_image(shamirs_k: int, shamirs_n: int):
    '''
    image_path: path to image
    return stego image
    '''
    # Первый этап
    # загрузка изображения
    image = Image.open(Path(IMAGE_PATH))
    # разбиение секрета на части
    secret = shamir_split_secret(SECRET, shamirs_k, shamirs_n)
    # Второй этап
    # подсчитываем вместимость w
    w = get_w(image.size, get_all_shares_len(secret))
    if w >= 1:
        # подсчитываем количество столбцов и строк, по формуле приведенной в статье строка всегда будет одна
        cols, rows = get_cols_rows(len(secret))
        # разбиваем изображение на блоки
        blocks = split_image_to_blocks(image, cols, rows)
        # встраиваем секрет в блоки
        blocks = embed_shares_to_blocks(blocks, secret)
        # склеиваем блоки в изображение
        stego_image = merge_blocks_to_image(blocks, cols, rows)
        # сохраняем изображение
        stego_image.save(Path(SAVE_PATH + FORMAT))
        # шифруем и сохраняем количество столбцов
        encrypted_cols = encrypt_num_cols_rsa(cols, load_rsa_key(KEY_FILENAME))
        with open(Path(SAVE_PATH + '_cols.txt'), 'wb') as f:
            f.write(encrypted_cols)
        return Path(SAVE_PATH + FORMAT)
    else:
        raise ValueError('Image is too small for this secret')


def decrypt_stego_image(stego_image: Path):
    '''
    stego_image: stego image
    return extracted secret
    '''
    # загружаем изображение
    image = Image.open(stego_image)
    # загружаем ключ
    key = load_rsa_key(KEY_FILENAME)
    # загружаем количество столбцов
    with open(Path(SAVE_PATH + '_cols.txt'), 'rb') as f:
        encrypted_cols = f.read()
    # расшифровываем количество столбцов
    num_cols = decrypt_num_cols_rsa(encrypted_cols, key)
    # подсчитываем количество строк
    num_rows = math.ceil(len(SECRET) / num_cols)
    # разбиваем изображение на блоки
    blocks = split_image_to_blocks(image, num_cols, num_rows)
    # извлекаем секрет из блоков
    shares = []
    for block in blocks:
        shares.append(extract_share_from_block(block))
    shares = [(i, long_to_bytes(int(j))) for i, j in shares]
    shares = set(shares)
    shares = list(shares)
    print('shares: ', shares)
    # восстанавливаем секрет
    secret = shamir_recover_shares(shares)
    return secret


stego_image(shamirs_k=3, shamirs_n=5)
print(decrypt_stego_image(Path(SAVE_PATH + FORMAT)))



















