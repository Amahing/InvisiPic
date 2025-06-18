__version__ = "1.0.0"
__date_last_update__ = "15.06.2025"
__author__ = "Amahing"


# ============================================================
# ===                Importing Libraries                   ===
# ============================================================


import sys, os

from bitarray import bitarray

from PIL import Image

import tkinter as tk
from tkinter import filedialog, scrolledtext
import ttkbootstrap as tb
from ttkbootstrap.constants import BOTH, X, W, SUCCESS

from Crypto.Cipher import ChaCha20
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256


# ============================================================
# ===                                                      ===
# ===                Stream Encryption                    ===
# ===                                                      ===
# ============================================================


def generate_keystream(password: str, length: int) -> bitarray:
    """
    Generates a keystream of specified length based on password using ChaCha20.
    :param password: Text password
    :param length: Number of bits to generate
    :return: Bit stream
    """

    salt = b"\x00" * 16 # ⚠️ THIS IS NOT SAFE. Randomness should be implemented here or the person should choose the value themselves
    nonce = b"\x00" * 8 # ⚠️ THIS IS NOT SAFE. Randomness should be implemented here or the person should choose the value themselves

    key = PBKDF2(password, salt, dkLen=32, count=100_000, hmac_hash_module=SHA256)
    cipher = ChaCha20.new(key=key, nonce=nonce)

    num_bytes = (length + 7) // 8
    keystream_bytes = cipher.encrypt(b"\x00" * num_bytes)

    keystream_bits = bitarray()
    keystream_bits.frombytes(keystream_bytes)

    return keystream_bits[:length]


def stream_cipher(data: bitarray, key: bitarray) -> bitarray:
    """
    Encrypts plaintext and keystream
    :param data: Plaintext bit stream
    :param key: Keystream bit stream
    :return: Encrypted bit stream
    """
    return data ^ key  # XOR operation between plaintext and keystream


# ============================================================
# ===                                                      ===
# ===                 Image Processing                    ===
# ===                                                      ===
# ============================================================


Image.MAX_IMAGE_PIXELS = None  # Remove limitations for large image processing
channel_map = {
    "R": [0],
    "G": [1],
    "B": [2],
    "RG": [0, 1],
    "GB": [1, 2],
    "RB": [0, 2],
    "RGB": [0, 1, 2],
}


def read_file_as_bits(filename: str) -> bitarray:
    """
    Reads a file and returns a bit array.

    :param filename: Path to the file to read
    :return: Bitarray type bit array
    """
    with open(filename, "rb") as f:
        byte_data = f.read()  # Reading file as bytes
        bits = bitarray()
    bits.frombytes(byte_data)  # Converting bytes to bit array
    return bits


def write_bits_to_file(bits: bitarray, filename: str) -> None:
    """
    Writes a bit array to a file.

    :param bits: Bit array to write
    :param filename: Path to save the file
    """
    with open(filename, "wb") as f:
        f.write(bits.tobytes())  # Converting bit array to bytes and writing to file


def decimal_to_binary(n: int) -> str:
    """
    Converts a decimal number to a binary string.

    :param n: Decimal number
    :return: String with 8-bit binary representation
    """
    return format(n, "08b")


def binary_to_decimal(b: str) -> int:
    """
    Converts a binary string to a decimal number.

    :param b: String with binary number
    :return: Decimal representation of the number
    """
    return int(b, 2)


def encode_image(
    cover_img: str,
    hidden_file: str,
    flag_end: str,
    channel: str,
    save_file: str,
    password: str,
    is_can_continue: bool,
) -> None:
    """Embeds a file into an image

    :param cover_img: Image to embed data into
    :param hidden_file: File to hide
    :param flag_end: End-of-file flag
    :param channel: Selected color channels for processing
    :param save_file: Filename for saving
    :param password: Password for stream encryption
    :param is_can_continue: Variable to continue code execution or stop it
    """

    # 1. Import the image
    try:
        img = Image.open(cover_img)
        if img.format != "PNG":
            insert_info_message(
                information_field_enc, "⚠️ Error: file is not in PNG format!"
            )
            is_can_continue = False
    except Exception as e:
        insert_info_message(information_field_enc, f"⚠️ Error opening file: {e}")
        is_can_continue = False

    if is_can_continue:
        insert_info_message(
            information_field_enc, "✅ Step 1/4: Image successfully imported"
        )

        # Get image size (stego-container)
        width, height = img.size
        image_bit_count = height * width * len(channel)

    # 2. Check for the presence of the file to hide
    if is_can_continue:
        if os.path.isfile(hidden_file):
            insert_info_message(
                information_field_enc,
                "✅ Step 2/4: File to hide successfully imported",
            )
        else:
            insert_info_message(
                information_field_enc,
                "⚠️ Step 2/4: Error importing file to hide, possibly incorrect filename or path!",
            )
            is_can_continue = False

    # 3. Convert file to hide to binary string
    if is_can_continue:
        insert_info_message(
            information_field_enc,
            "🕓 Performing file reading process into binary string...",
        )
        binary_stream = read_file_as_bits(hidden_file)
        binary_stream.extend(
            bitarray(flag_end)
        )  # Append end-of-file flag to binary stream

        insert_info_message(
            information_field_enc,
            "✅ Step 3/4: File to hide successfully converted to binary",
        )

    if is_can_continue:
        if image_bit_count < len(binary_stream):
            insert_info_message(
                information_field_enc,
                "⚠️ Step 4/4: Error! File to hide is larger than the image, choose a smaller file or a larger image!",
            )

            information_field_enc.insert(
                "end",
                "Current state:"
                f"\nstego-container size {image_bit_count} bits"
                f"\nfile to hide size {len(binary_stream)} bits",
            )
            is_can_continue = False

    # 4. Encryption
    if is_can_continue:
        insert_info_message(
            information_field_enc,
            "🕓 Performing process of writing binary string to image...",
        )
        # Create keystream
        keystream = generate_keystream(password, len(binary_stream))

        # XOR operation between keystream and file binary stream
        binary_stream = stream_cipher(binary_stream, keystream)

    # 5. Write encrypted binary stream to image
    if is_can_continue:
        pixels = img.load()
        counter = 0

        progress_encode["maximum"] = height
        progress_encode["value"] = 0

    if is_can_continue:
        if channel in channel_map:
            indices = channel_map[channel]

            for y in range(height):
                for x in range(width):
                    pixel = list(pixels[x, y][:3])  # Remove alpha channel
                    for i in indices:
                        if counter >= len(binary_stream):
                            break
                        pixel[i] = binary_to_decimal(
                            decimal_to_binary(pixel[i])[:-1]
                            + str(binary_stream[counter])
                        )
                        counter += 1

                    pixels[x, y] = tuple(pixel)
                progress_encode["value"] = y
                app.update_idletasks()

        img.save(save_file)
        insert_info_message(
            information_field_enc,
            "✅ Step 4/4: Secret content successfully embedded in image",
        )
        is_can_continue = True


def decode_image(
    codded_img: str,
    flag_end: str,
    channel: str,
    save_file: str,
    password: str,
    is_can_continue: bool,
) -> None:
    """Extracts a file from an image

    :param codded_img: Stego-image
    :param flag_end: End-of-file flag
    :param channel: Selected color channels for processing
    :param save_file: Filename for saving
    :param password: Password for stream encryption
    :param is_can_continue: Variable to continue code execution or stop it
    """

    def cut_string(origin: bitarray, flag: bitarray) -> bitarray:
        """
        Trims binary stream to first occurrence of end-flag.

        :param origin: Original bit array
        :param flag: Bit array serving as end flag
        :return: Trimmed bit array
        """
        index_iter = origin.search(flag)  # Search for flag occurrences in stream

        index = next(index_iter, None)  # Take first found index or None

        if index is None:
            insert_info_message(
                information_field_dec,
                "⚠️ Step 3/4: Error! End-flag not found!",
            )
            return None

        insert_info_message(
            information_field_dec,
            "✅ Step 3/4: Binary stream trimmed to hidden content end flag",
        )
        return origin[:index]  # Return trimmed bit array

    # 1. Import the image
    try:
        img = Image.open(codded_img)
        if img.format != "PNG":
            insert_info_message(
                information_field_dec, "⚠️ Error: file is not in PNG format!"
            )
            is_can_continue = False
    except Exception as e:
        insert_info_message(information_field_dec, f"⚠️ Error opening file: {e}")
        is_can_continue = False

    if is_can_continue:
        insert_info_message(
            information_field_dec, "✅ Step 1/4: Image successfully imported"
        )

        # Get image size (stego-container)
        width, height = img.size
        pixels = img.load()  # Load pixels for decoding

    # 2. Decode binary string from image
    output = []
    if is_can_continue:
        insert_info_message(
            information_field_dec,
            "🕓 Performing process of decoding binary string from image...",
        )

        progress_decode["maximum"] = height
        progress_decode["value"] = 0

        if channel in channel_map:
            indices = channel_map[channel]

            for y in range(height):
                for x in range(width):
                    pixel = pixels[x, y]

                    for i in indices:
                        output.append(decimal_to_binary(pixel[i])[-1:])
                progress_decode["value"] = y

        binary_stream = bitarray("".join(output))
        insert_info_message(
            information_field_dec,
            "✅ Step 2/4: Binary string decoded from image",
        )

    if is_can_continue:
        # 4. Decryption
        if password is not None:
            keystream = generate_keystream(
                password, len(binary_stream)
            )  # Create keystream

            binary_stream = stream_cipher(
                binary_stream, keystream
            )  # XOR operation between keystream and file binary stream

    if is_can_continue:
        try:
            bin_end_cutting = cut_string(binary_stream, bitarray(flag_end))
        except Exception:
            insert_info_message(
                information_field_dec,
                "⚠️ Step 3/4: Hidden content end flag not detected!",
            )
            is_can_continue = False

    if is_can_continue:
        write_bits_to_file(bin_end_cutting, save_file)
        insert_info_message(
            information_field_dec,
            "✅ Step 4/4: Secret content extracted from image",
        )
        is_can_continue = True


# ============================================================
# ===                                                      ===
# ===                 Graphical Interface                 ===
# ===                                                      ===
# ============================================================


def choose_file(entry_field, is_password=False, text_color="black"):
    # Select PNG image
    path = filedialog.askopenfilename(
        filetypes=[("PNG Images", "*.png")], title="Select PNG image"
    )
    if path:
        entry_field.delete(0, "end")
        entry_field.insert(0, path)
        entry_field.config(foreground=text_color)
        if is_password:
            entry_field.config(show="*")


def choose_any_file(entry_field, is_password=False, text_color="black"):
    # Select any file to embed
    path = filedialog.askopenfilename(
        filetypes=[("All Files", "*.*")], title="Select file to embed"
    )
    if path:
        entry_field.delete(0, "end")
        entry_field.insert(0, path)
        entry_field.config(foreground=text_color)
        if is_password:
            entry_field.config(show="*")


def choose_save_png(entry_field, is_password=False, text_color="black"):
    # Select location to save PNG image
    path = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG Images", "*.png")],
        title="Select location to save PNG",
    )
    if path:
        entry_field.delete(0, "end")
        entry_field.insert(0, path)
        entry_field.config(foreground=text_color)
        if is_password:
            entry_field.config(show="*")


def choose_save_any(entry_field, is_password=False, text_color="black"):
    # Select location to save any file
    path = filedialog.asksaveasfilename(title="Select location to save file")
    if path:
        entry_field.delete(0, "end")
        entry_field.insert(0, path)
        entry_field.config(foreground=text_color)
        if is_password:
            entry_field.config(show="*")


def enable_clipboard_shortcuts(widget):
    def paste(event=None):
        try:
            widget.event_generate("<<Paste>>")
            return "break"
        except Exception:
            pass

    def copy(event=None):
        try:
            widget.event_generate("<<Copy>>")
            return "break"
        except Exception:
            pass

    # Paste
    widget.bind("<Control-v>", paste)
    widget.bind("<Control-V>", paste)
    widget.bind(
        "<Control-KeyPress>", lambda e: paste() if e.keycode == 86 else None
    )  # keycode V

    # Copy
    widget.bind("<Control-c>", copy)
    widget.bind("<Control-C>", copy)
    widget.bind(
        "<Control-KeyPress>", lambda e: copy() if e.keycode == 67 else None
    )  # keycode C


def set_placeholder(
    widget,
    placeholder_text,
    is_password=False,
    placeholder_color="grey",
    text_color="black",
):
    is_entry = isinstance(widget, (tb.Entry, tk.Entry))
    is_text = isinstance(widget, (tk.Text, scrolledtext.ScrolledText))

    if is_entry:
        # Set initial placeholder in entry field
        widget.insert(0, placeholder_text)
        widget.config(foreground=placeholder_color)

        def on_focus_in(event):
            # When user clicks on field:
            # if there's a placeholder - clear it and enable normal text style
            if widget.get() == placeholder_text:
                widget.delete(0, "end")
                widget.config(foreground=text_color)
                # If it's a password field - enable asterisk masking
                if is_password:
                    widget.config(show="*")

        def on_focus_out(event):
            # If field loses focus and remains empty
            # set placeholder again and style it
            if not widget.get():
                widget.insert(0, placeholder_text)
                widget.config(foreground=placeholder_color)

    elif is_text:
        widget.insert("1.0", placeholder_text)
        widget.config(foreground=placeholder_color)

        def on_focus_in(event):
            if widget.get("1.0", "end-1c") == placeholder_text:
                widget.delete("1.0", "end")
                widget.config(foreground=text_color)

        def on_focus_out(event):
            if not widget.get("1.0", "end-1c").strip():
                widget.insert("1.0", placeholder_text)
                widget.config(foreground=placeholder_color)

    else:
        raise TypeError("Placeholder only supported for Entry or Text")

    widget.bind("<FocusIn>", on_focus_in)
    widget.bind("<FocusOut>", on_focus_out)


def insert_info_message(widget, message):
    widget.config(state="normal")  # Temporarily allow changes
    widget.insert("end", message + "\n")  # Add message
    widget.config(state="disabled")  # Disable editing


# === Main Window ===
app = tb.Window(themename="flatly")
icon = os.path.join(getattr(sys, '_MEIPASS', os.path.abspath(".")), "ico_app.ico")
app.iconbitmap(icon)
#app.iconbitmap("ico_app.ico")
app.title("Invisi Pic")
app.geometry("1280x820")
app.minsize(width=820, height=820)  # Minimum window size limit
app.maxsize(width=1920, height=820)  # Maximum window size limit


# === Main frame with grid ===
main_frame = tb.Frame(app)
main_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)

main_frame.columnconfigure(0, weight=1)
main_frame.columnconfigure(1, weight=1)
main_frame.rowconfigure(0, weight=1)

# === Left part (Encoding - hiding) ===
encode_frame = tb.LabelFrame(main_frame, text="Content Embedding")
encode_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

# === Right part (Decoding - extracting) ===
decode_frame = tb.LabelFrame(main_frame, text="Content Extraction")
decode_frame.grid(row=0, column=1, sticky="nsew", padx=(5, 0))


# === === === === === Encoding === === === === ===


# Field for selecting container image
select_container_image_enc = tb.Entry(encode_frame)
select_container_image_enc.pack(fill=X, padx=5, pady=5)
set_placeholder(select_container_image_enc, r"C:\Users\user\Pictures\your_image.png")
tb.Button(
    encode_frame,
    text="Select container image .png",
    command=lambda: choose_file(select_container_image_enc),
).pack(padx=5)

# Field for selecting file to hide
file_entry_enc = tb.Entry(encode_frame)
file_entry_enc.pack(fill=X, padx=5, pady=5)
set_placeholder(file_entry_enc, r"C:\Users\user\Documents\your_secret.docx")
tb.Button(
    encode_frame,
    text="Select file to hide",
    command=lambda: choose_any_file(file_entry_enc),
).pack(padx=5)

# Field for entering End-Flag
tb.Label(encode_frame, text="Enter content end flag:").pack(
    anchor=W, padx=5, pady=(10, 2)
)
flag_text_enc = scrolledtext.ScrolledText(encode_frame, height=3)
set_placeholder(flag_text_enc, "100101010111111111110000000001111111")
flag_text_enc.pack(fill=BOTH, padx=5, pady=2)

# Color channel selection
tb.Label(encode_frame, text="Select color channels for processing").pack(
    anchor=W, padx=5, pady=(10, 2)
)
combo_enc = tb.Combobox(
    encode_frame, values=["R", "G", "B", "RG", "GB", "RB", "RGB"], state="readonly"
)
combo_enc.current(0)
combo_enc.pack(fill=X, padx=5, pady=5)

# Field for saving result
save_entry_enc = tb.Entry(encode_frame)
save_entry_enc.pack(fill=X, padx=5, pady=5)
set_placeholder(save_entry_enc, r"C:\Users\user\Images\stego.png")
tb.Button(
    encode_frame,
    text="Select location to save stegocontainer .png",
    command=lambda: choose_save_png(save_entry_enc),
).pack(padx=5)

# Field for entering password
tb.Label(encode_frame, text="Password:").pack(anchor=W, padx=5, pady=(10, 2))
password_enc = tb.Entry(encode_frame, show="*")
password_enc.pack(fill=X, padx=5, pady=5)
set_placeholder(password_enc, "**********")


def handle_encoding():
    # Process encoding button click
    cover_img = select_container_image_enc.get()
    hidden_file = file_entry_enc.get()
    flag_end = flag_text_enc.get("1.0", "end").strip()
    channel = combo_enc.get()
    save_file = save_entry_enc.get()
    password = password_enc.get()

    # Clear field
    information_field_enc.config(state="normal")
    information_field_enc.delete("1.0", "end")  # Actual field clearing
    information_field_enc.config(state="disabled")

    # Call encoding function
    encode_image(
        cover_img=cover_img,
        hidden_file=hidden_file,
        flag_end=flag_end,
        channel=channel,
        save_file=save_file,
        password=password,
        is_can_continue=True,
    )


# Button to start encoding
tb.Button(
    encode_frame,
    text="Hide information",
    bootstyle=SUCCESS,
    command=handle_encoding,
).pack(pady=10)

# Progress bar label
label = tb.Label(encode_frame, text="Processing:", anchor=W)
label.pack(fill=X, padx=5, pady=2)

# Progress bar
progress_encode = tb.Progressbar(
    encode_frame, mode="determinate", bootstyle="success-striped"
)
progress_encode.pack(fill=X, padx=5, pady=2)

# Information display field
tb.Label(encode_frame, text="Information field:").pack(anchor=W, padx=5, pady=(10, 2))
information_field_enc = scrolledtext.ScrolledText(
    encode_frame, height=5, state="disabled"
)
information_field_enc.pack(fill=BOTH, expand=False, padx=5, pady=(0, 10))


# === === === === === Decoding === === === === ===


# Field for selecting stegocontainer
select_stegocontainer_dec = tb.Entry(decode_frame)
select_stegocontainer_dec.pack(fill=X, padx=5, pady=5)
set_placeholder(select_stegocontainer_dec, r"C:\Users\user\Pictures\your_stego.png")
tb.Button(
    decode_frame,
    text="Select stegocontainer .png",
    command=lambda: choose_file(select_stegocontainer_dec),
).pack(padx=5)

# Field for entering End-Flag
tb.Label(decode_frame, text="Enter content end flag:").pack(
    anchor=W, padx=5, pady=(10, 2)
)
flag_text_dec = scrolledtext.ScrolledText(decode_frame, height=3)
set_placeholder(flag_text_dec, "100101010111111111110000000001111111")
flag_text_dec.pack(fill=BOTH, padx=5, pady=2)

# Color channel selection
tb.Label(decode_frame, text="Select color channels for processing").pack(
    anchor=W, padx=5, pady=(10, 2)
)
combo_dec = tb.Combobox(
    decode_frame, values=["R", "G", "B", "RG", "GB", "RB", "RGB"], state="readonly"
)
combo_dec.current(0)
combo_dec.pack(fill=X, padx=5, pady=5)

# Field for saving result
save_entry_dec = tb.Entry(decode_frame)
save_entry_dec.pack(fill=X, padx=5, pady=5)
set_placeholder(save_entry_dec, r"C:\Users\user\Images\output.exe")
tb.Button(
    decode_frame,
    text="Select location to save extracted content",
    command=lambda: choose_save_any(save_entry_dec),
).pack(padx=5)

# Field for entering password
tb.Label(decode_frame, text="Password:").pack(anchor=W, padx=5, pady=(10, 2))
password_dec = tb.Entry(decode_frame, show="*")
password_dec.pack(fill=X, padx=5, pady=5)
set_placeholder(password_dec, "**********")


def handle_decoding():
    # Process decoding button click
    codded_img = select_stegocontainer_dec.get()
    flag_end = flag_text_dec.get("1.0", "end").strip()
    channel = combo_dec.get()
    save_file = save_entry_dec.get()
    password = password_dec.get()

    # Clear field
    information_field_dec.config(state="normal")
    information_field_dec.delete("1.0", "end")  # Actual field clearing
    information_field_dec.config(state="disabled")

    # Call decoding function
    decode_image(
        codded_img=codded_img,
        flag_end=flag_end,
        channel=channel,
        save_file=save_file,
        password=password,
        is_can_continue=True,
    )


# Button to start decoding
tb.Button(
    decode_frame,
    text="Extract hidden content",
    bootstyle=SUCCESS,
    command=handle_decoding,
).pack(pady=10)

# Progress bar label
label = tb.Label(decode_frame, text="Processing:", anchor=W)
label.pack(fill=X, padx=5, pady=2)

# Progress bar
progress_decode = tb.Progressbar(
    decode_frame, mode="determinate", bootstyle="success-striped"
)
progress_decode.pack(fill=X, padx=5, pady=2)

# Information display field
tb.Label(decode_frame, text="Information field:").pack(anchor=W, padx=5, pady=(10, 2))
information_field_dec = scrolledtext.ScrolledText(
    decode_frame, height=5, state="disabled"
)
information_field_dec.pack(fill=BOTH, expand=False, padx=5, pady=(0, 10))


# ===  === Allow paste from clipboard (Ctrl+V) ===  ===
for widget in [
    select_container_image_enc,
    file_entry_enc,
    flag_text_enc,
    save_entry_enc,
    password_enc,
    select_stegocontainer_dec,
    flag_text_dec,
    save_entry_dec,
    password_dec,
]:
    enable_clipboard_shortcuts(widget)


def main():
    """=== Launch the program with graphical interface ==="""
    app.mainloop()


if __name__ == "__main__":
    main()
