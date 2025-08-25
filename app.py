from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

# Configuração do banco de dados SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Modelo de Dados para o Formulário de Contato
class Contato(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    telefone = db.Column(db.String(20), nullable=True)
    mensagem = db.Column(db.Text, nullable=False)
    data_envio = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"Contato('{self.nome}', '{self.email}')"

# Rotas existentes do site
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/venda')
def venda():
    return render_template('venda.html')

@app.route('/aluguel')
def aluguel():
    return render_template('aluguel.html')

@app.route('/sobre')
def sobre():
    return render_template('sobre.html')

# Rota para a Página de Contato (agora processa o formulário)
@app.route('/contato', methods=['GET', 'POST'])
def contato():
    if request.method == 'POST':
        # Captura os dados do formulário
        nome = request.form['nome']
        email = request.form['email']
        telefone = request.form.get('telefone', '')
        mensagem = request.form['mensagem']
        
        # Cria um novo objeto Contato e salva no banco de dados
        novo_contato = Contato(
            nome=nome,
            email=email,
            telefone=telefone,
            mensagem=mensagem
        )
        db.session.add(novo_contato)
        db.session.commit()
        
        # Redireciona para a página principal ou uma página de sucesso
        return redirect(url_for('index'))
    
    # Se a requisição for GET, apenas renderiza o formulário
    return render_template('contato.html')


if __name__ == '__main__':
    # Cria o banco de dados e as tabelas
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)