import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify, g,  make_response
from werkzeug.utils import secure_filename
from jinja2 import TemplateNotFound
from flask_mysqldb import MySQL, MySQLdb
from flask_mail import Mail, Message
import cv2
import time
import os
import imghdr
import uuid
import bcrypt
import requests  
import json
import re
from werkzeug.security import check_password_hash
from functools import wraps

from ultralytics import YOLO
from datetime import datetime

from io import BytesIO
from xhtml2pdf import pisa

app = Flask(__name__)
app.secret_key = "savon"

# Folder upload untuk menyimpan gambar yang diunggah
UPLOAD_FOLDER = 'static/uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Load model YOLOv8
model = YOLO('models/best.pt')

# Allowed file types (jpg, jpeg, png)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Fungsi untuk memeriksa file yang di-upload
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Fungsi untuk melakukan deteksi penyakit pada gambar yang di-upload
def detect_disease_on_image(image_path):
    # Baca gambar
    img = cv2.imread(image_path)

    # Deteksi objek pada gambar menggunakan YOLOv8
    results = model(img)

    # Gambar bounding box dan prediksi pada gambar
    annotated_img = results[0].plot()

    # Simpan gambar yang sudah di-annotate
    output_image_path = os.path.join(app.config['UPLOAD_FOLDER'], 'detected_' + os.path.basename(image_path))
    cv2.imwrite(output_image_path, annotated_img)

    return output_image_path, results  # Mengembalikan path gambar hasil dan deteksi


app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'savon'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'savon9814@gmail.com'  
# app.config['MAIL_PASSWORD'] = 'jxwk gqxc nxnf liul'  
app.config['MAIL_PASSWORD'] = 'nmxs btrb bbpt cvji'
app.config['MAIL_DEFAULT_SENDER'] = 'dickyyahya25@gmail.com'  
mail = Mail(app)



#upload foto profil
UPLOAD_FOLDER_PROFILE = 'static/profile_pictures'
ALLOWED_EXTENSIONS_PROFILE = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER_PROFILE'] = UPLOAD_FOLDER_PROFILE

def allowed_file_profile(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_PROFILE

# Folder upload untuk menyimpan foto artikel
UPLOAD_FOLDER_ARTIKEL = 'static/uploads/artikels'
app.config['UPLOAD_FOLDER_ARTIKEL'] = UPLOAD_FOLDER_ARTIKEL

ALLOWED_EXTENSIONS_ARTIKEL = {'png', 'jpg', 'jpeg'}

def allowed_file_artikel(filename):
    # Memastikan file memiliki ekstensi yang diizinkan
    if not ('.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_ARTIKEL):
        return False, "Ekstensi file tidak diizinkan. Harus PNG, JPG, atau JPEG."
    # Memastikan nama file tidak kosong
    if filename.strip() == '':
        return False, "Nama file tidak boleh kosong."
    return True, "File valid."


# Folder upload untuk menyimpan video
UPLOAD_FOLDER_VIDEOS = 'static/uploads/videos'
app.config['UPLOAD_FOLDER_VIDEOS'] = UPLOAD_FOLDER_VIDEOS

ALLOWED_EXTENSIONS_VIDEO = {'mp4', 'avi', 'mov', 'mkv'}

def allowed_file_video(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_VIDEO
  

# start code for user
# Route untuk halaman utama
@app.route('/')
def index():
    return render_template('index.html')

# code login no captcha
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        # Proses login tanpa reCAPTCHA
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        curl.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = curl.fetchone()
        curl.close()

        if user is not None and user['is_verified']:
            if bcrypt.hashpw(password, user['password'].encode('utf-8')) == user['password'].encode('utf-8'):
                session['name'] = user['name']
                session['email'] = user['email']
                return redirect(url_for('index'))
            else:
                flash("Gagal, Email dan Password Tidak Cocok", "danger")
                return redirect(url_for('login'))
        else:
            flash("Gagal, User Tidak Terverifikasi atau Tidak Ditemukan", "danger")
            return redirect(url_for('login'))
    else:
        return render_template("login.html")
    

#code login/masuk + captcha
# @app.route('/login', methods=['POST', 'GET'])
# def login():
#     if request.method == 'POST':
#         recaptcha_response = request.form.get('g-recaptcha-response')
#         secret_key = '6Lfpqa4qAAAAAGAiZHEglq6-HbrLZqGYumUwpc6X'
#         recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        
#         # Verifikasi reCAPTCHA
#         recaptcha_data = {'secret': secret_key, 'response': recaptcha_response}
#         recaptcha_verify = requests.post(recaptcha_url, data=recaptcha_data)
#         recaptcha_result = recaptcha_verify.json()
        
#         if not recaptcha_result.get('success'):
#             flash("Gagal, reCAPTCHA tidak valid. Silakan coba lagi.", "danger")
#             return redirect(url_for('login'))
        
#         # Proses login setelah reCAPTCHA berhasil
#         email = request.form['email']
#         password = request.form['password'].encode('utf-8')
#         curl = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
#         curl.execute("SELECT * FROM users WHERE email=%s", (email,))
#         user = curl.fetchone()
#         curl.close()

#         if user is not None and user['is_verified']:
#             if bcrypt.hashpw(password, user['password'].encode('utf-8')) == user['password'].encode('utf-8'):
#                 session['name'] = user['name']
#                 session['email'] = user['email']
#                 return redirect(url_for('index'))
#             else:
#                 flash("Gagal, Email dan Password Tidak Cocok", "danger")
#                 return redirect(url_for('login'))
#         else:
#             flash("Gagal, User Tidak Terverifikasi atau Tidak Ditemukan", "danger")
#             return redirect(url_for('login'))
#     else:
#         return render_template("login.html")



# code register/daftar + no captcha
# @app.route('/register', methods=['POST', 'GET'])
# def register():
#     if request.method == 'GET':
#         return render_template('register.html')
#     else:
#         # Proses form tanpa reCAPTCHA
#         name = request.form['name']
#         email = request.form['email']
#         password = request.form['password']
#         confirm_password = request.form['confirm_password']

#         # Validasi password
#         if password != confirm_password:
#             return render_template('register.html', error='Passwords tidak sama')

#         password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
#         if not re.match(password_regex, password):
#             return render_template(
#                 'register.html',
#                 error='Password harus minimal 8 karakter, termasuk huruf besar, kecil, simbol, dan angka'
#             )

#         hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
#         verification_token = str(uuid.uuid4())

#         cur = mysql.connection.cursor()
#         cur.execute("INSERT INTO users (name, email, password, verification_token) VALUES (%s, %s, %s, %s)", 
#                     (name, email, hash_password, verification_token))
#         mysql.connection.commit()

#         send_verification_email(email, verification_token)
#         session['name'] = name
#         session['email'] = email
#         flash("Berhasil mendaftar! Silakan cek email Anda untuk verifikasi.", "success")
#         return redirect(url_for('login'))
    

#code register/daftar + captcha
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        # Ambil token reCAPTCHA dari request
        recaptcha_response = request.form.get('g-recaptcha-response')
        secret_key = "6Lfpqa4qAAAAAGAiZHEglq6-HbrLZqGYumUwpc6X"  # Secret key dari Google reCAPTCHA

        # Kirim request ke API reCAPTCHA untuk verifikasi
        recaptcha_url = 'https://www.google.com/recaptcha/api/siteverify'
        recaptcha_data = {
            'secret': secret_key,
            'response': recaptcha_response
        }
        recaptcha_verify = requests.post(recaptcha_url, data=recaptcha_data)
        recaptcha_result = recaptcha_verify.json()

        # Cek hasil verifikasi reCAPTCHA
        if not recaptcha_result.get('success'):
            return render_template('register.html', error='Verifikasi reCAPTCHA gagal. Silakan coba lagi.')

        # Proses form
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validasi email sudah terdaftar
        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing_user = cur.fetchone()
        if existing_user:
            return render_template('register.html', error='Email sudah terdaftar. Silakan gunakan email lain.')

        # Validasi password
        if password != confirm_password:
            return render_template('register.html', error='Passwords tidak sama')

        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_regex, password):
            return render_template(
                'register.html',
                error='Password harus minimal 8 karakter, termasuk huruf besar, kecil, simbol, dan angka'
            )

        hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        verification_token = str(uuid.uuid4())

        cur.execute("INSERT INTO users (name, email, password, verification_token) VALUES (%s, %s, %s, %s)", 
                    (name, email, hash_password, verification_token))
        mysql.connection.commit()

        send_verification_email(email, verification_token)
        session['name'] = name
        session['email'] = email
        flash("Berhasil mendaftar! Silakan cek email Anda untuk verifikasi.", "success")
        return redirect(url_for('login'))


# fungsi kirim verifikasi email
def send_verification_email(user_email, verification_token):
    # Buat URL verifikasi
    verification_url = url_for('verify_email', token=verification_token, _external=True)
    
    # Buat pesan email
    msg = Message('Email Verifikasi', recipients=[user_email])
    
    # Gunakan HTML untuk menyembunyikan URL
    msg.html = f"""
        <p>Halo,</p>
        <p>Klik link berikut untuk memverifikasi email Anda:</p>
        <a href="{verification_url}" target="_blank">Klik link berikut</a>
        <p>Jika Anda tidak mendaftarkan akun ini, abaikan email ini.</p>
    """
    
    # Kirim email
    mail.send(msg)

    #code verif email
@app.route('/verify/<token>')
def verify_email(token):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE verification_token = %s", (token,))
    user = cur.fetchone()

    if user:
        # Jika token valid, tandai email sebagai terverifikasi dan hapus token
        cur.execute("UPDATE users SET is_verified = TRUE, verification_token = NULL WHERE email = %s", (user['email'],))
        mysql.connection.commit()
        flash("Email berhasil diverifikasi! Sekarang Anda bisa login.", "success")
    else:
        flash("Link verifikasi tidak valid atau sudah kedaluwarsa.", "danger")

    return redirect(url_for('login'))

#code lupa password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        # Cari pengguna berdasarkan email
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            # Buat token reset password
            reset_token = str(uuid.uuid4())
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET reset_token = %s WHERE email = %s", (reset_token, email))
            mysql.connection.commit()

            # Kirim email reset password
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            send_reset_email(email, reset_url)

            flash("Link reset password telah dikirim ke email Anda.", "success")
            return redirect(url_for('login'))
        else:
            flash("Email tidak ditemukan.", "danger")

    return render_template('forgot_password.html')

#code fungsi send email
def send_reset_email(user_email, reset_url):
    msg = Message('Reset Password', recipients=[user_email])

    # Ubah ke format HTML untuk menyembunyikan URL di balik teks
    msg.html = f"""
        <p>Halo,</p>
        <p>Klik link berikut untuk mengatur ulang password Anda:</p>
        <a href="{reset_url}" target="_blank">Klik link berikut</a>
        <p>Jika Anda tidak meminta pengaturan ulang password, abaikan email ini.</p>
    """
    mail.send(msg)


#code rute reset password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM users WHERE reset_token = %s", (token,))
    user = cur.fetchone()

    if not user:
        flash("Token reset password tidak valid atau telah kedaluwarsa.", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validasi password
        if new_password != confirm_password:
            return render_template('reset_password.html', token=token, error='Passwords do not match')

        password_regex = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        if not re.match(password_regex, new_password):
            return render_template(
                'reset_password.html',
                token=token,
                error='Password harus minimal 8 karakter, termasuk huruf besar, kecil, simbol, dan angka'
            )

        # Hash password baru
        hash_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Perbarui password di database dan hapus token reset
        cur.execute("UPDATE users SET password = %s, reset_token = NULL WHERE email = %s", 
                    (hash_password, user['email']))
        mysql.connection.commit()
        flash("Password Anda berhasil diatur ulang. Silakan login.", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# code api cuaca
def get_weather_by_coordinates(lat, lon):
    api_key = '6215a9cd0ca28ebb047212b203336b94'  
    url = f'http://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={api_key}&units=metric'
    
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        weather = {
            'city': data['name'],
            'temperature': data['main']['temp'],
            'description': data['weather'][0]['description'],
            'icon': data['weather'][0]['icon'],
            'humidity': data['main']['humidity'],        
            'wind_speed': data['wind']['speed']          
        }
        return weather
    else:
        return None  



#code rute profil
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        # Ambil data dari form
        name = request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        

        # Update data ke database
        cur.execute("""
            UPDATE users 
            SET name = %s, phone = %s, address = %s 
            WHERE email = %s
        """, (name, phone, address, email))
        mysql.connection.commit()
        flash("Profil berhasil diperbarui", "success")
        return redirect(url_for('profile'))

    # Ambil data pengguna dari database
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    return render_template('profile.html', user=user)

# code edit profil
@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'email' not in session:
        return redirect(url_for('login'))

    email = session['email']
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    if request.method == 'POST':
        # Ambil data dari form
        name = request.form['name']
        phone = request.form['phone']
        address = request.form['address']
        

        file = request.files.get('profile_picture')
        if file and allowed_file_profile(file.filename):
            filename = f"{uuid.uuid4().hex}.{file.filename.rsplit('.', 1)[1].lower()}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER_PROFILE'], filename)
            file.save(file_path)

            cur.execute("""
                UPDATE users 
                SET profile_picture = %s WHERE email =%s
            """, (filename, email))

        # Update data ke database
        cur.execute("""
            UPDATE users 
            SET name = %s, phone = %s, address = %s 
            WHERE email = %s
        """, (name, phone, address, email))
        mysql.connection.commit()
        flash("Profil berhasil diperbarui", "success")
        # return redirect(url_for('profile'))

    # Ambil data pengguna dari database
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close()

    return render_template('edit_profile.html', user=user)

@app.before_request
def load_user_data():
    if 'email' in session:
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT name, profile_picture FROM users where email = %s", (session ['email'],))
        user = cur.fetchone()
        g.user = user
    else:
        g.user = None


# Route untuk menangani upload dan proses deteksi penyakit
@app.route('/upload', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    if file and allowed_file(file.filename):
        # Ambil ekstensi file
        file_ext = file.filename.rsplit('.', 1)[1].lower()

        # Generate nama file unik menggunakan UUID atau timestamp
        unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        # Lakukan deteksi penyakit pada gambar yang di-upload
        detected_image_path, results = detect_disease_on_image(file_path)

        # Ambil label dan confidence dari hasil deteksi
        detected_info = []
        penyakit_terdeteksi = None  

        if results and len(results[0].boxes) > 0: 
            for result in results[0].boxes:
                label = model.names[int(result.cls)]  
                confidence = round(float(result.conf), 2)  
                detected_info.append({'label': label, 'confidence': confidence})

                # Asumsi penyakit utama adalah deteksi pertama
                if penyakit_terdeteksi is None:
                    penyakit_terdeteksi = label

        # Simpan hasil deteksi ke dalam database history HANYA jika penyakit terdeteksi dan bukan "healthy"
        if penyakit_terdeteksi and penyakit_terdeteksi.lower() != "sehat" and 'email' in session:
            email = session['email']

            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO history (email, penyakit, image_path) VALUES (%s, %s, %s)",
                        (email, penyakit_terdeteksi, detected_image_path))
            mysql.connection.commit()
            cur.close()

        # Redirect ke halaman hasil deteksi
        return render_template('result.html', detected_image=detected_image_path, detected_info=detected_info)

    return redirect(request.url)

# Fungsi untuk mendeteksi objek secara realtime melalui webcam
def generate_frames():
    # Buka kamera video (index 0 untuk webcam)
    camera = cv2.VideoCapture(0)

    while True:
        success, frame = camera.read()  
        if not success:
            break
        else:
            # Deteksi objek menggunakan model YOLOv8
            results = model(frame)

            # Gambar bounding box pada frame
            annotated_frame = results[0].plot()

            # Convert frame to bytes
            ret, buffer = cv2.imencode('.jpg', annotated_frame)
            frame = buffer.tobytes()

            # Mengirim frame yang di-encode sebagai respons streaming video
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
            
#code Prediksi penyakit    
@app.route('/deteksi', methods=['GET', 'POST'])
def deteksi():
    if 'email' in session:
        return render_template("deteksi.html", hide=True)
    else:
        return redirect(url_for('index'))

#code artikel dan video
#code artikel dan video
@app.route ('/arvid')
def arvid():
    if 'email' in session:
            # Ambil artikel dari database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM artikels")  # Query untuk mengambil artikel
        artikels = cursor.fetchall()

        # Ambil video dari database
        cursor.execute("SELECT * FROM videos")  # Query untuk mengambil video
        videos = cursor.fetchall()
        return render_template("arvid.html",hide=True, artikels=artikels, videos=videos)
    else:
        return redirect(url_for('index'))
# code history
@app.route('/history')
def history():
    if 'email' in session:
        email = session['email']

        # Ambil nilai filter dari query string
        penyakit = request.args.get('penyakit')  
        start_date = request.args.get('start_date')  
        end_date = request.args.get('end_date')  
        page = request.args.get('page', 1, type=int)  # Halaman saat ini, default 1
        per_page = 5  # Jumlah data per halaman

        # Validasi tanggal
        if start_date and end_date:
            try:
                if datetime.strptime(start_date, '%Y-%m-%d') > datetime.strptime(end_date, '%Y-%m-%d'):
                    flash("Tanggal mulai tidak boleh lebih besar dari tanggal akhir", 'danger')
                    return redirect(url_for('history'))
            except ValueError:
                flash("Format tanggal tidak valid", 'danger')
                return redirect(url_for('history'))

        # Query dasar
        query = "SELECT penyakit, detected_at, image_path FROM history WHERE email = %s"
        values = [email]

        # Tambahkan filter berdasarkan input
        if penyakit and penyakit.strip():
            query += " AND penyakit = %s"
            values.append(penyakit)
        if start_date and start_date.strip():
            query += " AND DATE(detected_at) >= %s"
            values.append(start_date)
        if end_date and end_date.strip():
            query += " AND DATE(detected_at) <= %s"
            values.append(end_date)

        # Hitung total data untuk pagination
        count_query = f"SELECT COUNT(*) AS total FROM ({query}) AS subquery"
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(count_query, values)
        total_data = cur.fetchone()['total']
        cur.close()

        # Tambahkan limit dan offset untuk pagination
        offset = (page - 1) * per_page
        query += " ORDER BY detected_at DESC LIMIT %s OFFSET %s"
        values.extend([per_page, offset])

        # Eksekusi query
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute(query, values)
        history_data = cur.fetchall()
        cur.close()

        # Hitung jumlah deteksi untuk setiap penyakit
        penyakit_count = {}
        for row in history_data:
            penyakit_count[row['penyakit']] = penyakit_count.get(row['penyakit'], 0) + 1

        # Hitung total halaman
        total_pages = (total_data + per_page - 1) // per_page

        return render_template(
            "history.html",
            history_data=history_data,
            penyakit_filter=penyakit,
            start_date_filter=start_date,
            end_date_filter=end_date,
            penyakit_count=penyakit_count,
            total_pages=total_pages,
            current_page=page,
            per_page=per_page
        )
    else:
        return redirect(url_for('index'))


# code export penyakit user
@app.route('/history/export/pdf', methods=['GET'])
def export_history_pdf():
    if 'email' not in session:
        return redirect(url_for('index'))  # Pastikan user sudah login

    email = session['email']  # Ambil email dari sesi user

    # Ambil data history berdasarkan email user
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT penyakit, detected_at, image_path FROM history WHERE email = %s", (email,))
    history_data = cur.fetchall()
    cur.close()

    # Render template HTML ke PDF
    html = render_template('export_penyakit_pdf.html', history=history_data, email=email)

    # Buat PDF menggunakan BytesIO
    pdf_output = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf_output)

    # Pastikan PDF berhasil dibuat
    if pisa_status.err:
        return "Error generating PDF", 500

    # Atur respons untuk mengunduh file
    response = make_response(pdf_output.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"attachment; filename=history_{email}.pdf"
    return response





#code api json 
@app.route('/api/penyakit_count')
def penyakit_count():
    if 'email' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    email = session['email']
    
    # Mengambil data penyakit berdasarkan email pengguna
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT penyakit, COUNT(*) AS jumlah_deteksi
        FROM history
        WHERE email = %s
        GROUP BY penyakit
    """, (email,))
    penyakit_data = cur.fetchall()
    cur.close()

    # Menyiapkan data dalam format JSON
    penyakit_count = {row['penyakit']: row['jumlah_deteksi'] for row in penyakit_data}
    return jsonify(penyakit_count)


    

# code penyakit
@app.route('/penyakit/<nama_penyakit>')
def penyakit(nama_penyakit):
    try:
        # Ubah nama penyakit agar sesuai dengan konvensi penamaan file
        formatted_name = nama_penyakit.lower().replace(" ", "_")
        template = f'penyakit/{formatted_name}.html'
        return render_template(template, nama_penyakit=nama_penyakit)
    except TemplateNotFound:
        return render_template('404.html'), 404
    

# Route untuk mendeteksi objek secara realtime
@app.route('/realtime')
def realtime():
    return render_template('realtime.html')

# Route untuk menampilkan video feed secara realtime
@app.route('/video_feed')
def video_feed():
    return Response(generate_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

# code logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index')) 
# end code for user

# start code for admin
# code login admin
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Query database tabel admins
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM admins WHERE username = %s", (username,))
        admin = cur.fetchone()
        cur.close()

        # Validasi username dan password
        if admin and check_password_hash(admin['password'], password):
            session['admin_logged_in'] = True
            session['admin_username'] = admin['username']
            flash("Login berhasil!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Username atau password salah.", "danger")

    return render_template('admin/admin_login.html')

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_logged_in' not in session:
            flash("Anda harus login sebagai admin untuk mengakses halaman ini.", "danger")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function


# code dashboard admin
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Query untuk data statistik
    cur.execute("SELECT COUNT(*) AS total_users FROM users")
    total_users = cur.fetchone()['total_users']
    cur.execute("SELECT COUNT(*) AS total_disease FROM history")
    total_disease = cur.fetchone()['total_disease']
    cur.execute("SELECT COUNT(*) AS total_artikel FROM artikels")
    total_artikel = cur.fetchone()['total_artikel']
    cur.execute("SELECT COUNT(*) AS total_video FROM videos")
    total_video = cur.fetchone()['total_video']



    # Koordinat cuaca tegal
    lat, lon = -6.8797, 109.1256  
    weather = get_weather_by_coordinates(lat, lon)

    return render_template(
        'admin/admin_dashboard.html',
        total_users=total_users,
        total_disease=total_disease,
        total_artikel=total_artikel,
        total_video=total_video,
        weather=weather,
        
    )
    
#code api json penyakit pada chart user
@app.route('/api/penyakit_count_admin')
def penyakit_count_admin():
    # Mengambil data penyakit dari semua pengguna tanpa filter berdasarkan email
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("""
        SELECT penyakit, COUNT(*) AS jumlah_deteksi
        FROM history
        GROUP BY penyakit
    """)
    penyakit_data = cur.fetchall()
    cur.close()

    # Menyiapkan data dalam format JSON
    penyakit_count_admin = {row['penyakit']: row['jumlah_deteksi'] for row in penyakit_data}
    return jsonify(penyakit_count_admin)


# code admin user
@app.route('/admin/users', methods=['GET'])
@admin_required
def manage_users():
    per_page = 10  # Jumlah data per halaman
    page = request.args.get('page', 1, type=int)  # Ambil parameter `page`
    
    # Hitung offset dan nomor awal
    offset = (page - 1) * per_page
    start_number = offset + 1

    # Query dengan LIMIT dan OFFSET
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(
        "SELECT id, name, email, address FROM users LIMIT %s OFFSET %s",
        (per_page, offset)
    )
    users = cur.fetchall()
    cur.close()
    
    # Hitung total data
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT COUNT(*) AS total FROM users")
    total_users = cur.fetchone()['total']
    cur.close()
    
    total_pages = (total_users + per_page - 1) // per_page  # Hitung total halaman
    
    # Kirim data ke template
    return render_template(
        'admin/manage_users.html',
        users=users,
        page=page,
        total_pages=total_pages,
        start_number=start_number
    )


# code delete user
@app.route('/user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    try:
        # Buat cursor
        cur = mysql.connection.cursor()
        # Eksekusi query penghapusan
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        # Commit perubahan
        mysql.connection.commit()
        cur.close()
        flash('User berhasil dihapus!', 'success')
    except Exception as e:
        # Tangani error
        flash(f'Gagal menghapus user: {e}', 'error')
    return redirect('/admin/users')


# code admin artikel
@app.route('/admin/artikel', methods=['GET'])
@admin_required
def admin_artikel():
    per_page = 5  # Jumlah data per halaman
    page = request.args.get('page', 1, type=int)  # Ambil parameter `page`
    
    # Hitung offset dan nomor awal
    offset = (page - 1) * per_page
    start_number = offset + 1

    # Query dengan LIMIT dan OFFSET
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(
        "SELECT id, title, description, url, image_url FROM artikels LIMIT %s OFFSET %s",
        (per_page, offset)
    )
    artikels = cur.fetchall()
    cur.close()
    
    # Hitung total data
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT COUNT(*) AS total FROM artikels")
    total_artikels = cur.fetchone()['total']
    cur.close()
    
    total_pages = (total_artikels + per_page - 1) // per_page  # Hitung total halaman
    
    # Kirim data ke template
    return render_template(
        'admin/admin_artikel.html',
        artikels=artikels,
        page=page,
        total_pages=total_pages,
        start_number=start_number
    )


# code admin video
@app.route('/admin/video', methods=['GET'])
@admin_required
def admin_video():
    per_page = 5  # Jumlah data per halaman
    page = request.args.get('page', 1, type=int)  # Ambil parameter `page`
    
    # Hitung offset dan nomor awal
    offset = (page - 1) * per_page
    start_number = offset + 1

    # Query dengan LIMIT dan OFFSET
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(
        "SELECT id, title, description, video FROM videos LIMIT %s OFFSET %s",
        (per_page, offset)
    )
    videos = cur.fetchall()
    cur.close()
    
    # Hitung total data
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT COUNT(*) AS total FROM videos")
    total_videos = cur.fetchone()['total']
    cur.close()
    
    total_pages = (total_videos + per_page - 1) // per_page  # Hitung total halaman
    
    # Kirim data ke template
    return render_template(
        'admin/admin_video.html',
        videos=videos,
        page=page,
        total_pages=total_pages,
        start_number=start_number
    )

# code admin penyakit
@app.route('/admin/penyakit', methods=['GET'])
@admin_required
def admin_penyakit():
    per_page = 10  # Jumlah data per halaman
    page = request.args.get('page', 1, type=int)  # Ambil parameter `page`
    
    # Hitung offset dan nomor awal
    offset = (page - 1) * per_page
    start_number = offset + 1

    # Query dengan LIMIT dan OFFSET
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute(
        "SELECT id, email, penyakit, detected_at FROM history LIMIT %s OFFSET %s",
        (per_page, offset)
    )
    penyakit = cur.fetchall()
    cur.close()
    
    # Hitung total data
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT COUNT(*) AS total FROM history")
    total_penyakit= cur.fetchone()['total']
    cur.close()
    
    total_pages = (total_penyakit+ per_page - 1) // per_page  # Hitung total halaman
    
    # Kirim data ke template
    return render_template(
        'admin/admin_penyakit.html',
        penyakit=penyakit,
        page=page,
        total_pages=total_pages,
        start_number=start_number
    )
    

# code hapus penyakit
@app.route('/penyakit/<int:id>', methods=['POST'])
def delete_penyakit(id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("DELETE FROM history WHERE id = %s", (id,))
        mysql.connection.commit()
        cur.close()
        flash("Data penyakit berhasil dihapus.", "success")
    except Exception as e:
        flash(f"Terjadi kesalahan: {e}", "danger")
    return redirect('/admin/penyakit')


# code admin history
@app.route('/admin/history')
def admin_history():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))
    return render_template('admin/admin_dashboard.html')

# code admin logout
@app.route('/admin/logout', methods=['POST'])
def admin_logout():
    session.clear()  # Hapus semua data sesi
    flash("Anda telah logout.", "success")
    return redirect(url_for('admin_login'))

#code tambah artikel
@app.route('/admin/create/artikel', methods=['GET', 'POST'])
@admin_required
def admin_create_artikel():
    if request.method == 'POST':
        # Mengambil input dari formulir
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        url = request.form.get('url', '').strip()
        image = request.files.get('gambar')

        # Validasi input
        if not title or not description or not url:
            flash("Judul, deskripsi, dan URL harus diisi", "danger")
            return redirect(request.url)

        # Validasi file gambar
        image_url = None
        if image:
            is_valid, message = allowed_file_artikel(image.filename)
            if not is_valid:
                flash(message, "danger")
                return redirect(request.url)

            # Simpan gambar dengan nama unik
            filename = secure_filename(image.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER_ARTIKEL'], unique_filename)
            try:
                image.save(image_path)
                image_url = image_path.replace("\\", "/")  # Konversi ke format URL
            except Exception as e:
                flash(f"Terjadi kesalahan saat menyimpan gambar: {e}", "danger")
                return redirect(request.url)


        # Simpan data artikel ke database
        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO artikels (title, description, url, image_url) VALUES (%s, %s, %s, %s)", 
                (title, description, url, image_url)
            )
            mysql.connection.commit()
            cur.close()

            flash("Artikel berhasil ditambahkan", "success")
            return redirect(url_for('admin_artikel'))
        except Exception as e:
            flash(f"Terjadi kesalahan saat menyimpan data: {e}", "danger")
            return redirect(request.url)

    # Render template tambah artikel
    return render_template('admin/tambah_artikel.html')

#code edit artikel
@app.route('/admin/edit/artikel/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_artikel(id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

    # Ambil data artikel berdasarkan ID
    cur.execute("SELECT * FROM artikels WHERE id = %s", (id,))
    artikel = cur.fetchone()
    cur.close()

    if artikel is None:
        flash("Artikel tidak ditemukan", "danger")
        return redirect(url_for('admin_artikel'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        url = request.form['url']
        image = request.files.get('gambar')

        # Validasi input
        if not title or not description or not url:
            flash("Semua kolom harus diisi", "danger")
            return render_template('admin/edit_artikel.html', artikel=artikel)

        # Menyimpan gambar baru jika ada
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER_ARTIKEL'], filename)
            try:
                image.save(image_path)
                image_url = image_path.replace("\\", "/")  # Konversi backslash ke slash
            except Exception as e:
                flash(f"Terjadi kesalahan saat menyimpan gambar: {e}", "danger")
                return render_template('admin/edit_artikel.html', artikel=artikel)
        else:
            image_url = artikel['image_url']  # Menjaga gambar lama jika tidak ada gambar baru

        # Update artikel di database
        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                UPDATE artikels 
                SET title = %s, description = %s, url = %s, image_url = %s 
                WHERE id = %s
            """, (title, description, url, image_url, id))
            mysql.connection.commit()
            cur.close()

            flash("Artikel berhasil diperbarui", "success")
            return redirect(url_for('admin_artikel'))
        except Exception as e:
            flash(f"Terjadi kesalahan saat menyimpan data: {e}", "danger")
            return render_template('admin/edit_artikel.html', artikel=artikel)

    # Jika method GET, tampilkan form dengan data artikel
    return render_template('admin/edit_artikel.html', artikel=artikel)


# code hapus artikel
@app.route('/artikel/<int:id>', methods=['POST'])
@admin_required
def delete_artikel(id):
    # Membuka cursor untuk menghapus artikel berdasarkan id
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM artikels WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('Artikel berhasil dihapus', 'success')
    return redirect(url_for('admin_artikel'))  


#code tambah video
@app.route('/admin/create/video', methods=['GET', 'POST'])
@admin_required
def admin_create_video():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        # Cek apakah file diunggah
        if 'video' not in request.files:
            flash("Tidak ada file video yang diunggah", "danger")
            return redirect(request.url)
        
        video = request.files['video']
        
        # Validasi file
        if video.filename == '':
            flash("File video harus dipilih", "danger")
            return redirect(request.url)
        
        if video and allowed_file_video(video.filename):
            filename = secure_filename(video.filename)
            video_path = os.path.join(app.config['UPLOAD_FOLDER_VIDEOS'], filename)
            video.save(video_path)

            # Simpan informasi video ke database
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO videos (title, description, video) VALUES (%s, %s, %s)", 
                (title, description, video_path)
            )
            mysql.connection.commit()
            cur.close()

            flash("Video berhasil ditambahkan", "success")
            return redirect(url_for('admin_video'))
        else:
            flash("Format file tidak didukung", "danger")
            return redirect(request.url)
    
    return render_template('admin/tambah_video.html')


# code hapus video
@app.route('/video/<int:id>', methods=['POST'])
@admin_required
def delete_video(id):
    # Membuka cursor untuk menghapus video berdasarkan id
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM videos WHERE id = %s", (id,))
    mysql.connection.commit()
    cur.close()
    
    flash('video berhasil dihapus', 'success')
    return redirect(url_for('admin_video'))  


#code edit video
@app.route('/admin/edit/video/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit_video(id):
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    
    # Ambil data video berdasarkan ID
    cur.execute("SELECT * FROM videos WHERE id = %s", (id,))
    video = cur.fetchone()
    cur.close()

    if video is None:
        flash("Video tidak ditemukan", "danger")
        return redirect(url_for('admin_video'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        # File video baru (jika ada)
        file = request.files.get('video')

        # Validasi input
        if not title or not description:
            flash("Semua kolom harus diisi", "danger")
            return render_template('admin/edit_video.html', video=video)

        # Path video (gunakan yang lama jika tidak ada file baru)
        video_path = video['video']
        if file and file.filename != '':
            if allowed_file_video(file.filename):  # Pastikan format file valid
                filename = secure_filename(file.filename)
                video_path = os.path.join(app.config['UPLOAD_FOLDER_VIDEOS'], filename)
                file.save(video_path)
            else:
                flash("Format file video tidak didukung", "danger")
                return render_template('admin/edit_video.html', video=video)

        # Update data di database
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE videos 
            SET title = %s, description = %s, video = %s 
            WHERE id = %s
        """, (title, description, video_path, id))
        mysql.connection.commit()
        cur.close()

        flash("Video berhasil diperbarui", "success")
        return redirect(url_for('admin_video'))

    # Jika method GET, tampilkan form dengan data video
    return render_template('admin/edit_video.html', video=video)

# code export pdf user
@app.route('/admin/users/export/pdf', methods=['GET'])
@admin_required
def export_users_pdf():
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id, name, email, address FROM users")
    users = cur.fetchall()
    cur.close()
    
    # Render template ke HTML
    html = render_template('admin/export_pdf_user.html', users=users)
    
    # Buat PDF menggunakan BytesIO
    pdf_output = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf_output)
    
    # Pastikan PDF berhasil dibuat
    if pisa_status.err:
        return "Error generating PDF", 500
    
    # Atur respons untuk mengunduh file
    response = make_response(pdf_output.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=users_list.pdf"
    return response


# code export penyakit
@app.route('/admin/penyakit/export/pdf', methods=['GET'])
@admin_required
def export_penyakit_pdf():
    # Ambil data penyakit dari database
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT id, email, penyakit, detected_at FROM history")
    penyakit = cur.fetchall()
    cur.close()
    
    # Render template ke HTML
    html = render_template('admin/export_pdf_penyakit.html', penyakit=penyakit)
    
    # Buat PDF menggunakan BytesIO
    pdf_output = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf_output)
    
    # Pastikan PDF berhasil dibuat
    if pisa_status.err:
        return "Error generating PDF", 500
    
    # Atur respons untuk mengunduh file
    response = make_response(pdf_output.getvalue())
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = "attachment; filename=penyakit_list.pdf"
    return response

if __name__ == '__main__':
    app.run(debug=True)
