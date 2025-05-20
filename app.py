import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import io
from werkzeug.utils import secure_filename
from fpdf import FPDF
import gspread
from gspread_dataframe import get_as_dataframe
from google.oauth2.service_account import Credentials
import csv
import locale
import json

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = 'sua_chave_secreta_aqui'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializa DB e Login Manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

UPLOAD_FOLDER = os.path.join(basedir, 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# ------------------- MODELOS ------------------- #
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class MetaConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    app_id = db.Column(db.String(255))
    app_secret = db.Column(db.String(255))
    access_token = db.Column(db.Text)
    webhook_url = db.Column(db.String(500), nullable=True)

# ------------------- LOGIN ------------------- #
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form

        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe.')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Cadastro realizado com sucesso! Faça login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = 'remember' in request.form

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            return redirect(url_for('config'))
        flash('Credenciais inválidas.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ------------------- CONFIG META ------------------- #
@app.route('/config', methods=['GET', 'POST'])
@login_required
def config():
    meta = MetaConfig.query.filter_by(user_id=current_user.id).first()
    if request.method == 'POST':
        if not meta:
            meta = MetaConfig(user_id=current_user.id)
        meta.app_id = request.form['app_id']
        meta.app_secret = request.form['app_secret']
        meta.access_token = request.form['access_token']
        meta.webhook_url = request.form.get('webhook_url', None)
        db.session.add(meta)
        db.session.commit()
        flash('Dados salvos com sucesso.')
        return redirect(url_for('contas'))
    return render_template('config.html', meta=meta)

# ------------------- CONTAS / DASHBOARD ------------------- #
@app.route('/contas')
@login_required
def contas():
    meta = MetaConfig.query.filter_by(user_id=current_user.id).first()
    if not meta or not meta.access_token:
        flash('Token não configurado.')
        return redirect(url_for('config'))

    try:
        response = requests.get(
            'https://graph.facebook.com/v19.0/me/adaccounts',
            params={'access_token': meta.access_token}
        )
        data = response.json()

        if 'error' in data:
            flash('Erro na API: ' + data['error']['message'])
            return redirect(url_for('config'))

        contas_data = data.get('data', [])

        contas_formatadas = []
        for conta in contas_data:
            conta_id = conta.get('id')
            nome = conta.get('name', 'Sem nome')
            business = requests.get(
                f"https://graph.facebook.com/v19.0/{conta_id}",
                params={'fields': 'business', 'access_token': meta.access_token}
            ).json()
            bm_nome = business.get('business', {}).get('name', 'Desconhecido')
            contas_formatadas.append({
                'id': conta_id,
                'nome': nome,
                'business': bm_nome
            })

        return render_template('contas.html', contas=contas_formatadas)

    except Exception as e:
        flash('Erro ao buscar contas: ' + str(e))
        return redirect(url_for('config'))

@app.route('/dashboard/<conta_id>')
@login_required
def dashboard(conta_id):
    dados_mock = {
        'conta_id': conta_id,
        'cliques': 1234,
        'impressoes': 56789,
        'conversoes': 234,
        'ctr': '2.1%',
        'custo_total': 'R$ 1.234,56'
    }
    bms = {}  # Garante que bms sempre existe
    return render_template('dashboard.html', dados=dados_mock, bms=bms)

@app.route('/api/list-sheets')
def list_sheets():
    planilhas = [
        {'id': '1w7VPPYppc-RcK_aEAIZO4103KWGM7H2FWj4V_onUIE4', 'nome': 'Planilha 1'},
        {'id': '10tUstU0pmQ5efF5B6hQStsj5MNHlwVuFzFRwFnis9LA', 'nome': 'Planilha 2'},
        {'id': '1XSr6K7eiNNJGU8bapV2w5Dlpb_I5Xw0DwGu6AshLmxA', 'nome': 'Rs Motors'}
    ]
    return jsonify(planilhas)

@app.route('/api/sheets-metrics')
def sheets_metrics():
    sheet_id = request.args.get('sheet_id', '1w7VPPYppc-RcK_aEAIZO4103KWGM7H2FWj4V_onUIE4')
    creds = get_google_creds()
    gc = gspread.authorize(creds)
    spreadsheet = gc.open_by_key(sheet_id)
    worksheet = spreadsheet.sheet1
    df = get_as_dataframe(worksheet, evaluate_formulas=True, header=0)
    df.columns = [str(col).strip().lower() for col in df.columns]
    def get_num(possiveis):
        for nome in possiveis:
            for col in df.columns:
                if nome in col:
                    try:
                        return pd.to_numeric(df[col], errors='coerce').sum()
                    except Exception:
                        continue
        return 0
    alcance = get_num(['alcance'])
    impressoes = get_num(['impressões', 'impreções'])
    cpl = get_num(['custo por lead', 'cpr', 'custo por resultado'])
    gasto = get_num(['total gasto', 'valor gasto'])
    conversao = get_num(['resultados', 'ações no site', 'novos contatos'])
    receita = get_num(['receita'])
    roi = ((receita - gasto) / gasto) if gasto and receita else None
    return jsonify({
        'Alcance': int(alcance),
        'Impressões': int(impressoes),
        'Custo por Lead': round(float(cpl), 2),
        'Total Gasto': round(float(gasto), 2),
        'Conversão': int(conversao),
        'ROI': round(roi, 2) if roi is not None else '-'
    })

@app.route('/api/export-sheet')
def export_sheet():
    locale.setlocale(locale.LC_ALL, 'pt_BR.UTF-8')
    sheet_id = request.args.get('sheet_id')
    creds = get_google_creds()
    gc = gspread.authorize(creds)
    spreadsheet = gc.open_by_key(sheet_id)
    worksheet = spreadsheet.sheet1
    df = get_as_dataframe(worksheet, evaluate_formulas=True, header=0)
    df.columns = [str(col).strip().lower() for col in df.columns]
    def get_num(possiveis):
        for nome in possiveis:
            for col in df.columns:
                if nome in col:
                    try:
                        return pd.to_numeric(df[col], errors='coerce').sum()
                    except Exception:
                        continue
        return 0
    alcance = get_num(['alcance'])
    impressoes = get_num(['impressões', 'impreções'])
    cpl = get_num(['custo por lead', 'cpr', 'custo por resultado'])
    gasto = get_num(['total gasto', 'valor gasto'])
    conversao = get_num(['resultados', 'ações no site', 'novos contatos'])
    receita = get_num(['receita'])
    roi = ((receita - gasto) / gasto) if gasto and receita else None
    def fmt(n, dec=0):
        try:
            if dec == 0:
                return f"{int(n):,}".replace(",", ".")
            else:
                return f"{float(n):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
        except:
            return "-"
    # Lógica de sugestões igual ao dashboard
    sugestoes = []
    positivos = []
    if cpl <= 3:
        positivos.append('Excelente custo por lead.')
    elif cpl > 5:
        sugestoes.append('O custo por lead está elevado, tente otimizar seus anúncios.')
    else:
        sugestoes.append('O custo por lead está dentro da média, mas pode ser melhorado.')
    if alcance > 50000:
        positivos.append('Ótimo alcance, sua campanha está atingindo muitas pessoas.')
    elif alcance < 10000:
        sugestoes.append('O alcance está baixo, tente ampliar o público.')
    if conversao < 10:
        sugestoes.append('A conversão está baixa, avalie o criativo e o público.')
    elif conversao > 100:
        positivos.append('Ótima taxa de conversão.')
    if roi is not None and roi < 0:
        sugestoes.append('Atenção: o ROI está negativo, reveja o investimento.')
    elif roi is not None and roi > 0.2:
        positivos.append('Ótimo retorno sobre investimento (ROI).')
    if gasto > 10000:
        sugestoes.append('O investimento está alto, monitore o retorno.')
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 18)
    pdf.cell(0, 15, 'Relatório de Desempenho', 0, 1, 'C')
    pdf.set_font('Arial', '', 12)
    pdf.ln(5)
    pdf.set_fill_color(255, 215, 0)
    pdf.set_text_color(24, 24, 24)
    pdf.cell(60, 10, 'Métrica', 1, 0, 'C', True)
    pdf.cell(60, 10, 'Valor', 1, 1, 'C', True)
    pdf.set_text_color(0, 0, 0)
    pdf.set_fill_color(255,255,255)
    linhas = [
        ('Alcance', fmt(alcance)),
        ('Impressões', fmt(impressoes)),
        ('Custo por Lead', fmt(cpl, 2)),
        ('Total Gasto', fmt(gasto, 2)),
        ('Conversão', fmt(conversao)),
        ('ROI', f"{round(roi*100,2):,.2f}%".replace(",", "X").replace(".", ",").replace("X", ".") if roi is not None else '-')
    ]
    for met, val in linhas:
        pdf.cell(60, 10, met, 1, 0, 'C')
        pdf.cell(60, 10, str(val), 1, 1, 'C')
    pdf.ln(8)
    pdf.set_font('Arial', 'B', 13)
    pdf.cell(0, 10, 'Análise e Sugestões', 0, 1, 'L')
    pdf.set_font('Arial', '', 11)
    if positivos:
        pdf.set_text_color(0, 128, 0)
        pdf.cell(0, 8, 'Pontos positivos:', 0, 1, 'L')
        for p in positivos:
            pdf.cell(0, 7, f'- {p}', 0, 1, 'L')
    if sugestoes:
        pdf.set_text_color(200, 120, 0)
        pdf.cell(0, 8, 'Oportunidades:', 0, 1, 'L')
        for s in sugestoes:
            pdf.cell(0, 7, f'- {s}', 0, 1, 'L')
    pdf.set_text_color(120,120,120)
    pdf.ln(6)
    pdf.set_font('Arial', 'I', 10)
    pdf.cell(0, 10, 'Relatório gerado automaticamente pelo Dashboard IA Midas', 0, 1, 'C')
    pdf_bytes = pdf.output(dest='S').encode('latin1')
    output = io.BytesIO(pdf_bytes)
    output.seek(0)
    return send_file(
        output,
        mimetype='application/pdf',
        as_attachment=True,
        download_name='relatorio_customizado.pdf'
    )

# ------------------- INIT DB ------------------- #
with app.app_context():
    os.makedirs(os.path.join(basedir, 'instance'), exist_ok=True)
    db.create_all()

# Caminho para o arquivo de credenciais
def get_google_creds():
    creds_json = os.environ.get("GOOGLE_CREDENTIALS")
    creds_dict = json.loads(creds_json)
    return Credentials.from_service_account_info(creds_dict, scopes=[
        'https://www.googleapis.com/auth/spreadsheets',
        'https://www.googleapis.com/auth/drive'
    ])

gc = gspread.authorize(get_google_creds())

if __name__ == '__main__':
    app.run(debug=True)

