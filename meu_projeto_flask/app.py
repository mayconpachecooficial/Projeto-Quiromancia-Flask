from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from random import choice
from io import BytesIO
import os
import sqlite3
import hashlib

app = Flask(__name__)

# Lista de análises de quiromancia pré-definidas
QUIROMANCY_ANALYSES = [
    "Análise 1: Você tem uma grande linha da vida, indicando vitalidade.",
    "Análise 2: Sua linha do coração sugere uma pessoa apaixonada.",
    "Análise 3: A linha da cabeça revela uma mente analítica.",
    # Adicione mais análises conforme necessário
]

# Configuração do app Flask
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.config.update(
    MAIL_SERVER='smtp-mail.outlook.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get('MAIL_USERNAME', 'mayconmspalco@hotmail.com'),
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD', 'Mp06vA29')
)

mail = Mail(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def create_users_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('upload_file'))
    else:
        return redirect(url_for('home'))

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if request.method == 'POST':
        nome = request.form['name']
        email = request.form['email']
        telefone = request.form['phone']
        senha = request.form['password']
        confirmar_senha = request.form['confirm_password']

        if senha != confirmar_senha:
            return render_template('cadastro.html', error_message="As senhas não correspondem.")

        hashed_password = hashlib.sha256(senha.encode()).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            return render_template('cadastro.html', error_message="O e-mail já está cadastrado.")

        cursor.execute('INSERT INTO users (name, email, phone, password) VALUES (?, ?, ?, ?)',
                       (nome, email, telefone, hashed_password))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))

    return render_template('cadastro.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()

        if user and hashlib.sha256(senha.encode()).hexdigest() == user['password']:
            session['logged_in'] = True
            session['email'] = email
            return redirect(url_for('upload_file'))
        else:
            error_message = "Usuário ou senha incorretos."
            return render_template('login.html', error_message=error_message)

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            return redirect(request.url)

        # Gera o PDF diretamente da imagem enviada
        analysis_result = choice(QUIROMANCY_ANALYSES)
        pdf_path = generate_pdf(analysis_result, file)
        send_email(pdf_path, session.get('email'))

        return 'Arquivo enviado e análise realizada. Verifique seu e-mail.'
    return render_template('upload.html')

@app.route('/verificar_email', methods=['POST'])
def verificar_email():
    data = request.get_json()
    email = data.get('email')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    exists = cursor.fetchone() is not None
    conn.close()
    return jsonify({'exists': exists})

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_pdf(content, file):
    pdf_filename = os.path.splitext(file.filename)[0] + '.pdf'
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)

    # Cria um objeto PDF com múltiplas páginas
    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    story = []

    styles = getSampleStyleSheet()
    normal_style = styles['Normal']

    # Converte a imagem enviada para um objeto que o ReportLab pode usar
    image = Image(BytesIO(file.read()), width=400, height=200)
    story.append(image)

    story.append(Spacer(1, 12))
    story.append(Paragraph("Análise Quiromântica Detalhada:", normal_style))
    story.append(Spacer(1, 12))
    analysis_paragraph = Paragraph(content, normal_style)
    story.append(analysis_paragraph)

    doc.build(story)

    # Retorna o caminho para o PDF gerado
    return pdf_path


def send_email(pdf_path, recipient):
    if recipient:
        msg = Message('Sua Análise de Quiromancia', sender=app.config['MAIL_USERNAME'], recipients=[recipient])
        msg.body = 'Encontre em anexo a análise de sua quiromancia.'
        with app.open_resource(pdf_path) as fp:
            msg.attach(pdf_path, 'application/pdf', fp.read())
        mail.send(msg)

if __name__ == '__main__':
    create_users_table()
    app.run(debug=True)
