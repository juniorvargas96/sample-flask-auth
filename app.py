#cd Desktop/AULAS/Rockeseat/Python/modulo_4/sample-flask-auth
from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:admin123@127.0.0.1:3306/flask-crud' # Caminho do banco de dados

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

# Define a rota para onde o usuário será redirecionado se não estiver autenticado
login_manager.login_view = 'login'

""" 
Associa a função ao carregamento de usuário via ID da sessão.
Utilizado internamente pelo Flask-Login para recuperar o usuário atual.
"""
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(user_id)

""" 
Define a rota /login e permite apenas requisições POST.
Usada para autenticar o usuário e iniciar uma sessão.
"""
@app.route('/login', methods=["POST"])
def login():
  data = request.json
  username = data.get("username")
  password = data.get("password")

  if username and password:
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
      login_user(user)
      print(current_user.is_authenticated)
      return jsonify({"message": "Autenticação realizada com sucesso"})
  
  return jsonify({"message": "Credenciais inválidas"}), 400

""" 
Define a rota /logout e exige que o usuário esteja autenticado.
Finaliza a sessão do usuário atual.
"""
@app.route('/logout', methods=["GET"])
@login_required
def logout():
  logout_user()
  return jsonify({"message": "Logout realizado com sucesso!"})

""" 
Define a rota /user com método POST.
Cria um novo usuário no banco de dados com senha criptografada.
"""
@app.route('/user', methods=['POST'])
def create_user():
  data = request.json
  username = data.get("username")
  password = data.get("password")

  if username and password:
    hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
    user = User(username=username, password=hashed_password, role='user')
    db.session.add(user)
    db.session.commit()
    return jsonify({"message": "Usuario cadastrado com sucesso."})
  
  return jsonify({"message": "Dados invalido"}), 400

""" 
Define a rota /user/<id_user> com método GET.
Retorna o nome de usuário com base no ID informado.
Exige autenticação.
"""
@app.route('/user/<int:id_user>', methods=['GET'])
@login_required
def read_user(id_user):
  user = User.query.get(id_user)

  if user:
    return {"username": user.username}
  
  return jsonify({"message": "Usuario não encontrado"}), 404

""" 
Define a rota /user/<id_user> com método PUT.
Permite atualizar a senha do usuário. Exige autenticação.
Impede que usuários comuns atualizem outros usuários.
"""
@app.route('/user/<int:id_user>', methods=['PUT'])
@login_required
def update_user(id_user):
  data = request.json
  user = User.query.get(id_user)

  # Verifica se o usuário autenticado tem permissão para atualizar
  if id_user != current_user.id and current_user.role == "user":
    return jsonify({"message": "Operação não permitida"}), 403
  
  if user and data.get("password"):
    user.password = data.get("password")
    db.session.commit()
    return jsonify({"message": f"Usuario {id_user} atualizado com sucesso."})
  
  return jsonify({"message": "Usuario não encontrado"}), 404

""" 
Define a rota /user/<id_user> com método DELETE.
Permite apenas que administradores deletem outros usuários,
exceto a si mesmos.
"""
@app.route('/user/<int:id_user>', methods=['DELETE'])
@login_required
def delete_user(id_user):
  user = User.query.get(id_user)

  # Verifica se o usuário atual é admin e se não está tentando se deletar
  if current_user.role != 'admin':
    return jsonify({"message": "Operação não permitida"}), 403
  if id_user == current_user.id:
    return jsonify({"message": "Deleção não permitida"}), 403
  
  if user:
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": f"Usuario {id_user} deletado com sucesso"})
  
  return jsonify({"message": "Usuario não encontrado"})

# Inicia o servidor Flask no modo debug
if __name__ == '__main__':
  app.run(debug=True)
