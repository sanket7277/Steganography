import os
import uuid
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash
from werkzeug.utils import secure_filename
from steganography import (
    prepare_payload,
    encode_lsb,
    decode_lsb,
    parse_payload
)

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "bmp"}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_image(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


# -------------------------
# ROUTES
# -------------------------

@app.route('/')
def home():
    """Homepage with intro and navigation"""
    return render_template('home.html')

@app.route('/features')
def features():
    return render_template('features.html')


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')



@app.route('/encode', methods=['GET', 'POST'])
def encode():
    if request.method == 'GET':
        return render_template('index.html')

    cover_file = request.files.get('cover_image')
    password = request.form.get('password', '').strip()

    if not password:
        flash('Password is required for encoding.', 'danger')
        return redirect(url_for('encode'))

    if not cover_file or cover_file.filename == '':
        flash('Please upload a cover image.', 'danger')
        return redirect(url_for('encode'))
    if not allowed_image(cover_file.filename):
        flash('Unsupported cover image format.', 'danger')
        return redirect(url_for('encode'))

    cover_name = secure_filename(cover_file.filename)
    cover_ext = cover_name.rsplit('.', 1)[1].lower()
    cover_id = f"cover_{uuid.uuid4().hex}.{cover_ext}"
    cover_path = os.path.join(app.config['UPLOAD_FOLDER'], cover_id)
    cover_file.save(cover_path)

    payload_type = request.form.get('payload_type', 'text')

    try:
        if payload_type == 'text':
            text = request.form.get('secret_text', '')
            if text.strip() == '':
                flash('Please enter text to encode.', 'danger')
                return redirect(url_for('encode'))
            payload = prepare_payload(kind='text', text=text, password=password)
        else:
            secret_img_file = request.files.get('secret_image')
            if not secret_img_file or secret_img_file.filename == '':
                flash('Please upload a secret image.', 'danger')
                return redirect(url_for('encode'))
            if not allowed_image(secret_img_file.filename):
                flash('Unsupported secret image format.', 'danger')
                return redirect(url_for('encode'))

            secret_name = secure_filename(secret_img_file.filename)
            secret_ext = secret_name.rsplit('.', 1)[1].lower()
            secret_id = f"secret_{uuid.uuid4().hex}.{secret_ext}"
            secret_path = os.path.join(app.config['UPLOAD_FOLDER'], secret_id)
            secret_img_file.save(secret_path)

            with open(secret_path, 'rb') as f:
                secret_bytes = f.read()

            payload = prepare_payload(
                kind='image',
                blob=secret_bytes,
                file_ext=secret_ext,
                password=password
            )

        stego_filename = f"encoded_{uuid.uuid4().hex}.png"
        stego_path = os.path.join(app.config['UPLOAD_FOLDER'], stego_filename)
        encode_lsb(cover_path, payload, stego_path)

        flash('Data encoded successfully!', 'success')
        return render_template('index.html', stego_image=stego_filename)
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('encode'))


@app.route('/decode', methods=['GET', 'POST'])
def decode():
    if request.method == 'GET':
        return render_template('extract.html')

    stego_file = request.files.get('stego_image')
    password = request.form.get('password', '').strip()

    if not password:
        flash('Password is required for decoding.', 'danger')
        return redirect(url_for('decode'))

    if not stego_file or stego_file.filename == '':
        flash('Please upload a stego image.', 'danger')
        return redirect(url_for('decode'))
    if not allowed_image(stego_file.filename):
        flash('Unsupported stego image format.', 'danger')
        return redirect(url_for('decode'))

    stego_name = secure_filename(stego_file.filename)
    stego_ext = stego_name.rsplit('.', 1)[1].lower()
    stego_id = f"stego_{uuid.uuid4().hex}.{stego_ext}"
    stego_path = os.path.join(app.config['UPLOAD_FOLDER'], stego_id)
    stego_file.save(stego_path)

    try:
        payload_bytes = decode_lsb(stego_path)
        meta = parse_payload(payload_bytes, password=password)

        if meta['kind'] == 'text':
            return render_template('extract.html', extracted_text=meta['text'])
        else:
            recovered_ext = meta.get('file_ext', 'png')
            out_name = f"decoded_{uuid.uuid4().hex}.{recovered_ext}"
            out_path = os.path.join(app.config['UPLOAD_FOLDER'], out_name)
            with open(out_path, 'wb') as f:
                f.write(meta['blob'])
            return render_template('extract.html', extracted_image=out_name)
    except Exception as e:
        flash(f'Error: {e}', 'danger')
        return redirect(url_for('decode'))


@app.route('/static/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)


if __name__ == '__main__':
    app.run(debug=True)
