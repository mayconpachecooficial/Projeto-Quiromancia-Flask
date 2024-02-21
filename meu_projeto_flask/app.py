from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from random import choice
from io import BytesIO
from flask import current_app as app
import os
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key')

# Lista de análises de quiromancia pré-definidas"
QUIROMANCY_ANALYSES = ["""
\t \n<b>Linha da Vida:</b> Curta e começa no Monte de Vênus, sugerindo entusiasmo pela vida, mas uma tendência a esgotar energia rapidamente.
\t \n<b>Linha da Cabeça:</b> Retilínea e distinta, indicando uma abordagem prática e estruturada do pensamento.
\t \n<b>Linha do Coração:</b> Começa sob o dedo de Saturno, o que pode indicar uma abordagem cuidadosa e, às vezes, cautelosa em relação às emoções e relacionamentos.
\t \n<b>Monte da Lua:</b> A presença do monte implica uma forte intuição e uma inclinação para a criatividade.
\t \n<b>Monte de Vênus:</b> Está relacionado à expressão e afetos emocionais, e sua proeminência pode indicar uma personalidade amorosa e apaixonada.
\t \n<b>Dedo de Júpiter:</b> Representa liderança e ambição. Uma pessoa com um dedo de Júpiter proeminente pode ser vista como autoritária e com desejo de controle.
\t \n<b>Dedo de Saturno:</b> Associado à responsabilidade e ao amor pela estrutura. Um dedo de Saturno longo pode indicar uma pessoa com uma abordagem séria da vida.
\t \n<b>Dedo do Sol:</b> Relacionado a criatividade, fama e sucesso. Um dedo do Sol bem formado sugere uma inclinação para as artes ou para ser o centro das atenções.
\t \n<b>Dedo de Mercúrio:</b> Ligado à comunicação e ao comércio. Um dedo de Mercúrio proeminente indica habilidades comunicativas e, muitas vezes, uma natureza comercial ou persuasiva.
\t \n<b>Linha do Sol (também conhecida como Linha do Apolo):</b> Não representada neste diagrama, mas se presente, é uma indicação de sucesso e reconhecimento.
\t \n<b>Linha do Casamento:</b> Também não mostrada aqui, mas quando aparece, revela informações sobre as relações íntimas e casamentos significativos.
\t \n<b>Linha da Saúde:</b> Ausente neste esquema, mas se visível, pode indicar questões de saúde ou vitalidade.
\t \n<b>Linha da Riqueza:</b> Não está presente no diagrama. Se estivesse, poderia dar pistas sobre a prosperidade material da pessoa.
\t \n<b>Linha do Destino:</b> Não especificada aqui, mas normalmente corre do pulso até o dedo de Saturno, indicando o grau em que a vida da pessoa é afetada por fatores externos versus auto-determinação.
"""]


# Configuração do app Flask
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
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def update_password(email, new_password):
    hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
    conn.commit()
    conn.close()


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

        analysis_result = choice(QUIROMANCY_ANALYSES)
        pdf_path = generate_pdf(analysis_result, file)
        recipient_email = session.get('email')
        additional_pdf_path = 'adicional/quiromancia.pdf'  # Coloque o caminho real do arquivo adicional aqui

        send_email(pdf_path, recipient_email, additional_pdf_path)

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

@app.route('/esqueci-minha-senha', methods=['GET', 'POST'])
def esqueci_minha_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        # Verifique se o e-mail existe no banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        if user:
            token = serializer.dumps(email, salt='email-reset')
            reset_url = url_for('redefinir_senha', token=token, _external=True)
            send_reset_email(email, reset_url)
            flash('Um email com instruções para redefinir sua senha foi enviado para você.')
            return redirect(url_for('login'))
        else:
            flash('E-mail não encontrado. Por favor, tente novamente.')
    return render_template('esqueci_minha_senha.html')

@app.route('/redefinir-senha', methods=['GET', 'POST'])
def redefinir_senha():
    token = request.args.get('token', None)
    if request.method == 'POST' and token:
        try:
            email = serializer.loads(token, salt='email-reset', max_age=3600)
        except SignatureExpired:
            flash('O link para redefinição de senha expirou.')
            return redirect(url_for('esqueci_minha_senha'))
        except BadSignature:
            flash('O link para redefinição de senha é inválido.')
            return redirect(url_for('esqueci_minha_senha'))
        
        nova_senha = request.form.get('nova_senha')
        confirmar_senha = request.form.get('confirm_password')
        app.logger.info('Passwords retrieved from form')  # Log de depuração
        
        if nova_senha != confirmar_senha:
            flash('Passwords do not match.')
            app.logger.warning('Passwords do not match')  # Log de aviso
            return redirect(url_for('redefinir_senha', token=token))
        
        update_password(email, nova_senha)
        app.logger.info('Password updated successfully')  # Log de sucesso
        flash('Your password has been updated.')
        return redirect(url_for('login'))
    elif token:
        return render_template('redefinir_senha.html', token=token)
    else:
        flash('No reset token provided.')
        return redirect(url_for('home'))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_pdf(content, file):
    pdf_filename = os.path.splitext(file.filename)[0] + '.pdf'
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)

    doc = SimpleDocTemplate(pdf_path, pagesize=letter)
    story = []

    styles = getSampleStyleSheet()
    custom_style = ParagraphStyle(
        'CustomStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=20,
        spaceAfter=10,
        alignment=TA_JUSTIFY,
        leftIndent=20
)

    image = Image(BytesIO(file.read()), width=400, height=200)
    story.append(image)

    story.append(Spacer(1, 12))
    story.append(Paragraph("Análise Quiromântica Detalhada:", custom_style))
    story.append(Spacer(1, 12))
    analysis_paragraph = Paragraph(content, custom_style)
    story.append(analysis_paragraph)

    doc.build(story)

    return pdf_path

def send_email(pdf_path, recipient, additional_pdf_path):
    if recipient:
        msg = Message('Sua Análise de Quiromancia', sender=app.config['MAIL_USERNAME'], recipients=[recipient])
        msg.body = 'Encontre em anexo a análise de sua quiromancia e informações adicionais.'
        with app.open_resource(pdf_path) as fp:
            msg.attach("analise_quiromancia.pdf", 'application/pdf', fp.read())
        with app.open_resource(additional_pdf_path) as fp:
            msg.attach("informacoes_adicionais.pdf", 'application/pdf', fp.read())
        mail.send(msg)


def send_reset_email(email, reset_url):
    msg = Message('Redefinir Senha', 
                  sender=app.config['MAIL_USERNAME'], 
                  recipients=[email])
    msg.body = f'Para redefinir sua senha, clique no link a seguir: {reset_url}'
    mail.send(msg)

if __name__ == '__main__':
    create_users_table()
    app.run(debug=True)
