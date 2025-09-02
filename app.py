from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from datetime import datetime
import secrets, os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_hex(16)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static/uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# -------------------------
# MODELOS
# -------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)

class Contato(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    telefone = db.Column(db.String(20), nullable=True)
    mensagem = db.Column(db.Text, nullable=False)
    data_envio = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class SiteConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    logo = db.Column(db.String(200), nullable=True)
    banner = db.Column(db.String(200), nullable=True)

class Card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descricao = db.Column(db.Text, nullable=False)
    imagem = db.Column(db.String(200), nullable=True)

# -------------------------
# LOGIN MANAGER
# -------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# -------------------------
# ADMIN
# -------------------------
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

    column_labels = {
        'titulo': 'Título',
        'descricao': 'Descrição',
        'imagem': 'Imagem',
        'logo': 'Logo',
        'banner': 'Banner'
    }

class MyAdminIndex(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        return super(MyAdminIndex, self).index()

admin = Admin(
    app,
    name='Painel Administrativo',
    template_mode='bootstrap4',
    index_view=MyAdminIndex()
)

admin.add_view(SecureModelView(SiteConfig, db.session, name="Configuração do Site"))
admin.add_view(SecureModelView(Card, db.session, name="Cards"))

# -------------------------
# ROTAS
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        senha = request.form['senha']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.senha, senha):
            login_user(user)
            return redirect(url_for('admin.index'))
        else:
            flash("E-mail ou senha incorretos", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
def index():
    site_config = SiteConfig.query.first()
    cards = Card.query.all()
    return render_template('index.html', site_config=site_config, cards=cards)

@app.route('/contato', methods=['GET', 'POST'])
def contato():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        telefone = request.form.get('telefone', '')
        mensagem = request.form['mensagem']
        novo_contato = Contato(nome=nome, email=email, telefone=telefone, mensagem=mensagem)
        db.session.add(novo_contato)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('contato.html')

# -------------------------
# CRIAR BANCO E ADMIN USER
# -------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@site.com").first():
        senha_hash = bcrypt.generate_password_hash("123456").decode('utf-8')
        user = User(email="admin@site.com", senha=senha_hash)
        db.session.add(user)
        db.session.commit()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
