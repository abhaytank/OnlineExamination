from flask import Flask, render_template ,flash, redirect, url_for, session, request, logging, g
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from logging import FileHandler, WARNING
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from passlib.hash import sha256_crypt
from flask_mysqldb import MySQL

app = Flask(__name__)
app.config.from_pyfile('config.cfg')

#init MySQL
mysql = MySQL(app)
#init flask-mail
mail = Mail(app)

s = URLSafeTimedSerializer('Thisisasecret!')

@app.route('/')
def index():
	session.pop('user', None)
	return render_template("home.html")

@app.route('/about')
def about():
    return render_template("about.html")

class LoginForm(Form):
    email = StringField('email', [validators.Length(min=6, max=50)])
    password = PasswordField('password', [
        validators.DataRequired(),
		validators.Length(min=8)
        ])

@app.route("/login", methods = ["GET","POST"])
def login():
	session.pop('user',None)
	form = LoginForm(request.form)
	if request.method == 'POST' and form.validate():
		email = form.email.data
		cur  = mysql.connection.cursor()
		result = cur.execute('SELECT * FROM users WHERE email = %s',[email])
		if result > 0:
			data = cur.fetchone()
			db_password = str(data['password'])
			cur.close()
			print('DATABASE PASSWORD = '+db_password)
			if sha256_crypt.verify(form.password.data,db_password):
				file_handler = FileHandler('errorlog.txt')
				file_handler.setLevel(WARNING)
				app.logger.addHandler(file_handler)
				session['user'] = email
				print('ENTERED')
				return redirect(url_for('dashboard'))
			else:
				main_reset_url =  request.host_url+'reset'
				message = 'Wrong password. Click on link to reset password ' + main_reset_url
				flash(message,'danger')
		else:
			flash('User not registered. Please Register First','danger')
	return render_template("login.html",form=form)

class RegisterForm(Form):
    username = StringField('username', [validators.Length(min=4, max=25)])
    email = StringField('email', [validators.Length(min=6, max=50)])
    password = PasswordField('password', [
        validators.DataRequired(),
		validators.Length(min=8),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('confirm')

@app.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm(request.form)
	if request.method == 'POST' and form.validate():
		username = form.username.data
		email = form.email.data
		password = sha256_crypt.encrypt(str(form.password.data))
		print(username,email,password)
		cur = mysql.connection.cursor()
		x = cur.execute('SELECT id FROM users WHERE email = %s',[email])
		if x > 0:
			flash("Email already taken","danger")
			return redirect(url_for("register"))
		else:
			cur.execute('INSERT INTO users(username,email,password) VALUES( %s, %s, %s)',(username,email,password))
			link = activate_link(email,cur)

	        #commit to DB
			mysql.connection.commit()
			flash("You are now registered. Activate the link sent to you and Login","success")
			cur.close()
	return render_template('register.html', form=form)


def activate_link(email,cur):
	token = s.dumps(email, salt='email-confirm')
	msg = Message('Confirm Email', sender='yourautomatedmail@example.com', recipients=[email])
	result = cur.execute("SELECT id FROM users WHERE email = %s",[email])
	data = cur.fetchone()
	print("DATA FETCHED : ")
	print(data)
	id = str(data['id'])
	print(id)
	parameter  = 'confirm_email/'+id+'/'+token
	link = request.host_url + parameter
	print("THE LINK IS : ",link)
	msg.body = 'Your link is {}'.format(link)
	mail.send(msg)
	return(link)

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' in session:
        user = request.cookies.get('session')
        g.courses = {
			'Java':'Java is a general-purpose computer-programming language that is concurrent, class-based, object-oriented, and specifically designed to have as few implementation dependencies as possible',
			'Python':'Python is an interpreted high-level programming language for general-purpose programming. Created by Guido van Rossum and first released in 1991, Python has a design philosophy that emphasizes code readability, notably using significant whitespace.',
			'C++':'C++ is a general-purpose programming language. It has imperative, object-oriented and generic programming features, while also providing facilities for low-level memory manipulation.',
			'C':'C is a general-purpose, imperative computer programming language, supporting structured programming, lexical variable scope and recursion, while a static type system prevents many unintended operations.',
			'HTML':'Hypertext Markup Language is the standard markup language for creating web pages and web applications. With Cascading Style Sheets and JavaScript, it forms a triad of cornerstone technologies for the World Wide Web.'
			}
        return render_template('dashboard.html', courses = g.courses, user = user)
    else:
        return redirect(url_for('login'))

class ResetForm(Form):
	email = StringField('email', [validators.Length(min=6, max=50)])

@app.route('/reset', methods=['GET', 'POST'])
def reset():
	form = ResetForm(request.form)
	if request.method == 'POST' and form.validate():
		email = form.email.data
		cur = mysql.connection.cursor()
		result = cur.execute('SELECT id FROM users WHERE email = %s',[email])
		if result >	0:
			data = cur.fetchone()
			id = str(data['id'])
			link = reset_link(email,id)
			flash('Password Reset Link is sent to your Email ID','success')
		else:
			flash('Enter valid email Address... Email not registered','danger')
	return render_template('reset.html',form=form)

def reset_link(email,id):
	token = s.dumps(email, salt='reset-pass')
	msg = Message('Reset Password', sender='yourautomatedmail@example.com', recipients=[email])
	parameter  = 'reset_password/'+id+'/'+token
	link = request.host_url + parameter
	print("THE LINK IS : ",link)
	msg.body = 'Your link is {}'.format(link)
	mail.send(msg)
	return(link)

class ResetPasswordForm(Form):
    password = PasswordField('password', [
        validators.DataRequired(),
		validators.Length(min=8),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('confirm')

@app.route('/logout')
def logout():
	session.pop('user',None)
	return redirect(url_for('index'))

@app.route('/test', methods=['GET', 'POST'])
def test():
    form = request.form
    if request.method == 'POST':
        option = request.form['optradio']
        print(option)
        flash(option)
    return render_template('test.html')

@app.route('/<option>/<user_id>/<token>',methods=['GET', 'POST'])
def selector(option,user_id,token):
	if option == 'confirm_email':
		try:
			link = s.loads(token, salt='email-confirm', max_age=3600)
		except SignatureExpired:
			return '<h1>The token is expired!</h1>'
		cur = mysql.connection.cursor()
		cur.execute('UPDATE users SET activate_stat = 1 where id = %s',[user_id])
        #commit to DB
		mysql.connection.commit()
		cur.close()
		host = request.host_url
		return render_template('activated.html' , host=host)

	elif option == 'reset_password':
		try:
			link = s.loads(token, salt='reset-pass', max_age=3600)
		except SignatureExpired:
			return '<h1>The token is expired!</h1>'
		form = ResetPasswordForm(request.form)
		if request.method == 'POST' and form.validate():
			password = sha256_crypt.encrypt(str(form.password.data))
			cur = mysql.connection.cursor()
			cur.execute('UPDATE users SET password = %s where id = %s',[password,user_id])
			mysql.connection.commit()
			cur.close()
			flash('Password has been reseted Successfully','success')
		return render_template('reset_land.html',form=form)

#This module is under production. JavaScript module will be added
	elif option == 'test':
		if token == request.cookies.get('session'):
			g.test = []
			g.orignal_answers = {}
			g.final_answers = {}
			cur = mysql.connection.cursor()
			query = 'select * from '+user_id
			try:
				result = cur.execute(query)
				data = cur.fetchall()
				for row in data:
					dict = {}
					print(row)
					id = row['id']
					dict['id'] = id
					question = row['question']
					print(question)
					dict['question'] = question
					answers = [row['ch1'],row['ch2'],row['ch3'],row['ch4']]
					print(answers)
					answers = list(filter(None.__ne__,answers))
					print(answers)
					dict['answers'] = answers
					orignal_answer = row['answer']
					print('Sub dictionary is')
					print(dict)
					g.test.append(dict)
					g.orignal_answers[question] = orignal_answer
				print(g.test)
				print("--------------------------------------------------------------------")
				print(g.orignal_answers)
				if request.method == 'POST':
					form_question = request.form['question']
					print('Form question : ',form_question)
					form_answer = request.form['answer']
					print('Form asnwer : ',form_answer)
					g.final_answers[form_question] = form_answer
					print(g.final_answers)
				print('Final answer')
				print(g.final_answers)
			except Exception as e:
				return e
			return render_template('test.html', test = g.test)
		else:
			return 'Session not recognized or is Corrupt.'

if __name__ == "__main__":
	app.secret_key='forky123'
	app.run(debug = True )
