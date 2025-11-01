from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os

# ======================================================
#  APP CONFIGURATION
# ======================================================
app = Flask(__name__)
app.secret_key = 'secure_app_key'

UPLOAD_FOLDER = 'static/uploads'
KEY_FOLDER = 'keys'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

PRIVATE_KEY_FILE = os.path.join(KEY_FOLDER, 'private.pem')
PUBLIC_KEY_FILE = os.path.join(KEY_FOLDER, 'public.pem')


# ======================================================
#  RSA KEY GENERATION
# ======================================================
def generate_keys():
    """Generate RSA key pair if not already present."""
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Save private key
        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Save public key
        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )


generate_keys()


# ======================================================
#  ROUTES
# ======================================================

@app.route('/')
def index():
    return render_template('index.html')


# ------------------------------------------------------
#  Upload document for signing
# ------------------------------------------------------
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    return redirect(url_for('sign_document', filename=file.filename))


# ------------------------------------------------------
#  Sign document
# ------------------------------------------------------
@app.route('/sign/<filename>')
def sign_document(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    with open(file_path, "rb") as f:
        data = f.read()

    with open(PRIVATE_KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    sig_filename = f"{filename}.sig"
    sig_path = os.path.join(UPLOAD_FOLDER, sig_filename)
    with open(sig_path, "wb") as f:
        f.write(signature)

    return redirect(url_for('success', filename=sig_filename))


# ------------------------------------------------------
#  Verify document form
# ------------------------------------------------------
@app.route('/verify')
def verify():
    return render_template('verify.html')


# ------------------------------------------------------
#  Verify document signature
# ------------------------------------------------------
@app.route('/verify', methods=['POST'])
def verify_signature():
    file = request.files['file']
    sig_file = request.files['signature']

    if not file or not sig_file:
        flash('Both files are required for verification!', 'danger')
        return redirect(url_for('verify'))

    #  Input validation: only accept .sig file
    if not sig_file.filename.lower().endswith('.sig'):
        flash('Invalid signature file format! Please upload a valid .sig file.', 'warning')
        return redirect(url_for('verify'))

    file_data = file.read()
    signature_data = sig_file.read()

    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            signature_data,
            file_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        result = " The document signature is VALID."
        status = "success"
    except Exception:
        result = " The document signature is INVALID."
        status = "danger"

    return render_template('verify_result.html', result=result, status=status)


# ------------------------------------------------------
#  Success page (after signing)
# ------------------------------------------------------
@app.route('/success/<filename>')
def success(filename):
    return render_template('success.html', signed_file=filename)


# ------------------------------------------------------
#  Share signed file
# ------------------------------------------------------
@app.route('/share/<filename>')
def share(filename):
    share_url = request.url_root + 'static/uploads/' + filename
    return render_template('share.html', share_url=share_url)


# ------------------------------------------------------
#  Download file route
# ------------------------------------------------------
@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


# ======================================================
#  RUN APPLICATION
# ======================================================
if __name__ == '__main__':
    app.run(debug=True)
