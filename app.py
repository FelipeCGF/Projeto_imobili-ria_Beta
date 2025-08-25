from flask import Flask, render_template

app = Flask(__name__)

# Página inicial
@app.route('/')
def index():
    return render_template('index.html')

# Página de venda
@app.route('/venda')
def venda():
    return render_template('venda.html')

# Página de aluguel
@app.route('/aluguel')
def aluguel():
    return render_template('aluguel.html')

# Página sobre
@app.route('/sobre')
def sobre():
    return render_template('sobre.html')

# Página de contato
@app.route('/contato')
def contato():
    return render_template('contato.html')


if __name__ == '__main__':
    app.run(debug=True, port=5000)
