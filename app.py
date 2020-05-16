from flask import Flask, render_template, redirect,url_for,session,logging,flash , request
from data import clients
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

#config mysql
app.config['MYSQL_HOST']='localhost'
app.config['MYSQL_USER']='root'
app.config['MYSQL_PASSWORD']='PASSWORD'
app.config['MYSQL_DB']='SHIPPINGAPP'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#init mysql
mysql = MySQL(app)

clients = clients()


@app.route('/')
def hello_world():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

class Registerform(Form):
    name = StringField('Name', [validators.length(min=1,max=50)])
    username = StringField('Username', [validators.length(min=4,max=25)])
    email = StringField('Email', [validators.length(min=6,max=20)])
    password = PasswordField('Password', [validators.DataRequired(),
                                          validators.equal_to('confirm', message='Passwords do not match')])
    confirm = PasswordField('Confirm Password')

@app.route('/register',methods = ['GET','POST'])
def register():
    form = Registerform(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        #create cursor
        cur = mysql.connection.cursor()
        cur.execute("insert into users (name,email,username,password) values (%s,%s,%s,%s)",(name,email,username,password))

        #commit to db
        mysql.connection.commit()

        #close connection
        cur.close()

        flash('YOU ARE NOW REGISTERED AND CAN LOGIN','success')
        redirect(url_for('register'))

    return render_template('register.html', form=form)

#user login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        #get form fields
        username = request.form['username']
        password_candidate = request.form['password']

        #create cursor
        cur = mysql.connection.cursor()

        #get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s",[username])

        if result > 0:
            #get stored with hash
            data = cur.fetchone()
            password = data['password']

            # compare passwords
            if sha256_crypt.verify(password_candidate , password):
                app.logger.info('PASSWORD MATCHED')
                #passed - we need session
                session['logged_in']= True
                session['username'] = username

                flash('You are now logged in','success')
                return redirect(url_for('dashboard'))

            else:
                app.logger.info('Invalid login')
                error = 'Invalid login'
                return render_template('login.html', error=error)
            #close connection
            cur.close()

        else:
            app.logger.info('NO USER')
            error = "USERNAME NOT FOUND"
            return render_template('login.html',error=error)
    return render_template('login.html')

#check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized,Please login', 'danger')
            return redirect(url_for('login'))
    return wrap



#logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out','success')
    return redirect(url_for('login'))

#Dashboard
@app.route('/Dashboard')
@is_logged_in
def dashboard():
    return render_template('Dashboard.html')

@app.route('/orders')
@is_logged_in
def orders():
    return render_template('orders.html', clients=clients)

@app.route('/order/<string:id>/')
@is_logged_in
def order(id):
    return render_template('order.html', id=id)


if __name__ == '__main__':
    app.secret_key= 'secret123'
    app.run(debug=True)
