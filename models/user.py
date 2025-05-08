from database import db  # Importa a instância do banco de dados configurada em 'database.py'

from flask_login import UserMixin  # Importa a classe UserMixin, que adiciona funcionalidades padrão de autenticação ao modelo do usuário

class User(db.Model, UserMixin):
  # id (int), username (text), password(text), role (text)

  id = db.Column(db.Integer, primary_key=True)  # Coluna ID: chave primária, valor inteiro, identifica unicamente cada usuário

  username = db.Column(db.String(80), nullable=False, unique=True)  # Coluna username: armazena o nome de usuário, obrigatório e único

  password = db.Column(db.String(80), nullable=False)  # Coluna password: armazena a senha do usuário, obrigatória

  role = db.Column(db.String(80), nullable=False, default="user")  # Coluna role: define o papel do usuário (ex: 'user' ou 'admin'), padrão é 'user'
