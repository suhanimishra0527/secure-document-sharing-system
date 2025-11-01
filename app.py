from flask import Flask, render_template, request, send_from_directory
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Initialize Flask app
app = Flask(__name__)

# Folder where uploaded files are stored
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed file extensions
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'txt'}

# Create uploads folder if it doesn’t exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Function to check if file type is allowed
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ==============================
# 🔹 ROUTES
# ==============================

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return render_template('error.html', message="No file part in the request.")
    
    file = request.files['file']
    if file.filename == '':
        return render_template('error.html', message="No file selected for upload.")
    
    if file and allowed_file(file.filename):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        return render_template('signed.html', filename=file.filename)
    else:
        return render_template('error.html', message="File type not allowed. Upload PDF, DOC, DOCX, JPG, JPEG, PNG, or TXT.")


# Route to download files
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# ==============================
# 🔐 DIGITAL SIGNATURE FUNCTIONS
# ==============================

# Generate RSA key pair (private + public)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))


# Sign a file using the private key
def sign_file(file_path):
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    with open(file_path, "rb") as f:
        file_data = f.read()

    signature = private_key.sign(
        file_data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as sig_file:
        sig_file.write(signature)

    return sig_path


# Route to sign uploaded document
@app.route('/sign/<filename>')
def sign_document(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists("private_key.pem"):
        generate_keys()  # Generate keys if not found

    sig_file = sign_file(file_path)
    return render_template("signed.html", filename=filename, sig_file=os.path.basename(sig_file))


# ==============================
# ✅ VERIFY SIGNATURE
# ==============================

@app.route('/verify', methods=['GET', 'POST'])
def verify_document():
    if request.method == 'POST':
        file = request.files['file']
        signature = request.files['signature']

        if not file or not signature:
            return render_template('error.html', message="Please upload both file and signature.")

        file_data = file.read()
        signature_data = signature.read()

        # Load public key
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())

        try:
            public_key.verify(
                signature_data,
                file_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return render_template('verify.html', result="✅ Signature is valid!")
        except Exception:
            return render_template('verify.html', result="❌ Signature is invalid or file has been modified.")
    return render_template('verify.html')


# ==============================
# 🚀 RUN APP
# ==============================
if __name__ == "__main__":
    app.run(debug=True)
