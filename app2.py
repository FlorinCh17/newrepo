from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, after_this_request
from flask_sslify import SSLify  # Import SSLify for HTTPS redirection
from blockchain import Blockchain
import os
from werkzeug.utils import secure_filename
from datetime import timedelta, datetime
import urllib.parse
import urllib.parse
import populateIdentity
from flask_mail import Mail, Message
import secrets
import smtplib, ssl
from email.message import EmailMessage
import threading

app = Flask(__name__)
sslify = SSLify(app)  # Enable HTTPS redirection


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.permanent_session_lifetime = timedelta(minutes =30)



# Dummy user class. Replace this with your actual User model.
class User():
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username
        # Creating a Blockchain
        Blockchain.start_observer()
blockchain = Blockchain('127.0.0.1', 5000)

def send_email(CNP, reason):
    user_info_list = blockchain.ToBeDetermined.get(CNP, [])
    print("send email")
    print(user_info_list)
    if user_info_list:
        user_info = user_info_list[0]
        print(user_info)
        email_receiver = user_info.get('email')
        name = user_info.get('name', 'User')
        
        if email_receiver is None:
            flash("Email address not found for the user")
            return
        
        email_sender = 'chi.florin17@gmail.com'  # Replace with your email address
        
        subject = 'Account Creation Response'
        if reason == 1:
            message = "You have problems with the Criminal Record document and with ID document."
        elif reason ==2:
            message = "You have problems with the Criminal Record document."
        elif reason ==3:
            message = "You have problems with the ID document."
        
        if reason == 1 or message == 2 or message == 3:
            body = f"""
            <html>
                <body>
                    <h2>Dear {name},</h2>
                    <p>We regret to inform you that your account creation request was rejected due to the following reason:</p>
                    <p><strong>{message}</strong></p>
                    <p>Please rectify the issue and try again.</p>
                </body>
            </html>
            """
        elif message == 4: 
            body = f"""
            <html>
                <body>
                    <h2>Dear {name},</h2>
                    <p>Thank you for using our platform</p>
                    <p><strong>To acces the file please use your name and last 6 characters from CNP</strong></p>
                    <p>Example: johnsmith123456</p>
                </body>
            </html>
            """
        em = EmailMessage()
        em['From'] = email_sender
        em['To'] = email_receiver
        em['Subject'] = subject
        em.set_content(body, subtype='html')  # Set HTML content

        context = ssl.create_default_context()

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(email_sender, 'obex qkao eirw meqp')  # Replace with your email password
                smtp.sendmail(email_sender, email_receiver, em.as_string())
            flash("Rejection email sent successfully")
        except Exception as e:
            flash(f"An error occurred while sending the rejection email: {e}")


def send_verification_email(private_key):
    mfa_code = secrets.randbelow(10000)  # Generate a random 4-digit code
    session['mfa_code'] = f'{mfa_code:04}'  # Format the code as a 4-digit string with leading zeros if necessary
    
    # Parcurge fiecare cheie și valoare din blockchain.Identity_dict
    for key, user_info_list in blockchain.Identity_dict.items():
        # Verifică dacă există informații despre utilizator
        if user_info_list:
            # Extrage primul dicționar de informații despre utilizator
            user_info = user_info_list[0]
            # Accesează email-ul utilizatorului
            if 'email' in user_info:
                email = user_info['email']
                print(f"Private Key: {key}, Email: {email}")
            else:
                print(f"No email found for private key: {key}")
        else:
            print(f"No user info found for private key: {key}")

    # Înainte de a continua, trebuie să te asiguri că există informații despre utilizator pentru cheia privată
    if user_info:
        # Accesează email-ul utilizatorului
        email_receiver = user_info.get('email')
        
        if email_receiver is None:
            flash("Email address not found for the user")
            return redirect(url_for('login'))

        email_sender = 'chi.florin17@gmail.com'  # Replace with your email address

        subject = 'Multi-Factor Authentication - Verification Code'
        body = f"""
        <html>
            <body>
                <h2>Your verification code is:</h2>
                <p><strong>{mfa_code}</strong></p>
            </body>
        </html>
        """

        em = EmailMessage()
        em['From'] = email_sender
        em['To'] = email_receiver
        em['Subject'] = subject
        em.set_content(body, subtype='html')  # Set HTML content

        context = ssl.create_default_context()

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(email_sender, 'obex qkao eirw meqp')  # Replace with your email password
                smtp.sendmail(email_sender, email_receiver, em.as_string())
            flash("Verification code sent successfully")
        except Exception as e:
            flash(f"An error occurred while sending the verification email: {e}")
            return redirect(url_for('login'))
    

@app.route('/verify_mfa_email', methods=['GET', 'POST'])
def verify_mfa_email():
    if request.method == 'POST':
        mfa_code = request.form.get('mfa_code')
        if 'mfa_code' in session and session['mfa_code'] == mfa_code:
            # MFA code correct, proceed to user page
            session.pop('mfa_code', None)  # Remove the stored MFA code from session
            private_key = session.pop('private_key', None)
            session.permanent = True
            session["user"] = private_key
            return redirect(url_for('userPage'))
        else:
            flash("Your MFA code is wrong")
            return render_template('verify_mfa_email.html')
    else:
        return render_template('verify_mfa_email.html')


def is_voting_period(start_date, end_date):
    current_time = datetime.now()
    if start_date is None and end_date is None:
        return False
    return start_date <= current_time <= end_date

@app.route('/set_voting_period', methods=['POST'])
def set_voting_period():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")
        start_date_str = request.form.get('start_date')
        end_date_str = request.form.get('end_date')

        # Convertiți șirurile în obiecte datetime
        start_date = datetime.strptime(start_date_str, "%Y-%m-%dT%H:%M")
        end_date = datetime.strptime(end_date_str, "%Y-%m-%dT%H:%M")

        blockchain.set_voting_period(start_date, end_date)
        flash("The START and END date is set")

        return render_template("finalResults.html", identity_contestants=blockchain.Identity_contestants, start_date=blockchain.voting_start_date, end_date = blockchain.voting_end_date, case = 1)
    else:
        return redirect(url_for('index'))


@app.route('/finalResults', methods = ['POST', 'GET'])
def finalResults():
    if "user" in session:
        user = session["user"]
        if not is_voting_period(start_date=blockchain.voting_start_date, end_date=blockchain.voting_end_date):
            if user not in blockchain.Identity_admin and user in blockchain.Identity_dict:
                flash(f"{blockchain.Identity_dict[user][0]['name']}", "error")
                sorted_contestants = sorted(blockchain.Identity_contestants.items(), key=lambda x: max(y['vot'] for y in x[1]), reverse=True)
                return render_template("finalResults.html", identity_contestants=sorted_contestants, start_date=blockchain.voting_start_date, end_date = blockchain.voting_end_date, case = 0)
            else: 
                flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")
                return render_template("finalResults.html", identity_contestants=blockchain.Identity_contestants, start_date=blockchain.voting_start_date, end_date = blockchain.voting_end_date, case = 1)
        else:
            if user not in blockchain.Identity_admin and user in blockchain.Identity_dict:
                return redirect(url_for('userPage'))
            else: 
                flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")
                return render_template("finalResults.html", identity_contestants=blockchain.Identity_contestants, start_date=blockchain.voting_start_date, end_date = blockchain.voting_end_date, case = 1)
    else:
        return redirect(url_for('login'))

@app.route('/index', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        private_key = request.form.get('Private Key')
        password = request.form.get('password')

        # Check if there is such a private key in the admin list
        if private_key in blockchain.Identity_admin and private_key in blockchain.Users:
            if Blockchain.check_password(password, blockchain.Users[private_key]):
                # If user is an admin, proceed directly to admin dashboard
                session.permanent = True
                session["user"] = private_key
                return redirect(url_for('admindashboard'))
            else: 
                flash("Your password is wrong")
                return render_template('login.html')

        # Check if there is such a private key in the user list
        elif private_key in blockchain.Users and private_key in blockchain.Identity_dict:
            # Check password first
            if Blockchain.check_password(password, blockchain.Users[private_key]):
                # Password correct, now prompt for MFA
                session['private_key'] = private_key
                
                send_verification_email(private_key)
                return redirect(url_for('verify_mfa_email'))
            else: 
                flash("Your password is wrong")
                return render_template('login.html')
        else:
            flash("There is no such Private Key in the user list")
            return render_template('login.html')
    else:
        # For GET requests, render the login template
        return render_template('login.html')

@app.route('/request_queue', methods = ['GET', 'POST'])
def request_queue():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")
        if request.method == 'POST':
            PwCR = request.form.get('myCheckbox1')
            PwID = request.form.get('myCheckbox2')
            alienated = request.form.get('myCheckbox3')
            residence = request.form.get('myCheckbox4')
            ## tratam cazurile pentru a trimite email-uri. 
            name = request.form.get('name')
            date_of_birth = request.form.get('date_of_birth')
            CNP = request.form.get('CNP')
            nationality = request.form.get('nationality')
            criminal_record = request.form.get('criminal_record')
            email = request.form.get('email')
            if PwCR == "Yes" and PwID =="Yes":
                send_email(CNP, 1)
                pass
            elif PwCR == "Yes":
                send_email(CNP, 2)
                rejected_user_data = blockchain.ToBeDetermined.pop(CNP, None)
                blockchain.RejectedRequests[CNP] = rejected_user_data
                

                pass
            elif PwID == "Yes":
                send_email(CNP, 3)
                rejected_user_data = blockchain.ToBeDetermined.pop(CNP, None)
                blockchain.RejectedRequests[CNP] = rejected_user_data
            else:
                private_key = Blockchain.generatePrivateKey()
                print("this is my private key")
                print(private_key)
                #populateIdentity.populate_identity_dict(private_key, name, date_of_birth, CNP, criminal_record, nationality, case4, case3)
                populateIdentity.populate_identity_dict(private_key, name, date_of_birth, CNP, criminal_record, nationality, residence, alienated, email)
                rejected_user_data = blockchain.ToBeDetermined.pop(CNP, None)
                send_email(CNP, 4)
                return redirect(url_for('admindashboard'))


            

    else:
        return redirect(url_for('login'))
    return render_template('admindashbord.html',  identity_dict = blockchain.ToBeDetermined)

@app.route('/admindashbord')
def admindashboard():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")

    else:
        return redirect(url_for('login'))
    return render_template('admindashbord.html',  identity_dict = blockchain.ToBeDetermined)

@app.route('/findCandidate', methods=['GET', 'POST'])
def findCandidate():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")
        
        if request.method == 'POST':
            # Inițializare lista pentru valorile formularului
            form_values = {
                'name': request.form.get('name'),
                'date_of_b': request.form.get('date_of_birth'),
                'CNP': request.form.get("CNP"),
                'criminal_records': request.form.get("criminal_record"),
                'nationality': request.form.get('nationality')
            }

            # Cautare potrivire în blockchain.Identity_dict
            found_candidates = []
            for key, values_list in blockchain.Identity_dict.items():
                for values_dict in values_list:
                    if all(form_values[key] == values_dict[key] for key in form_values):
                        found_candidates.append(key)

            # Afisare rezultate
            if found_candidates:
                flash(f"Found candidate: {', '.join(found_candidates)}")
            else:
                flash("There is no person with these descriptions")

    else:
        return redirect(url_for('login'))

    return render_template('candidateManagement.html')


@app.route('/submitCandidate', methods=['GET', 'POST'])
def submitCandidate():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")
        if request.method == 'POST':
            name = request.form.get('submit_name')
            private_key = request.form.get('submit_private_key')
            party = request.form.get('political_party')
            picture = request.files['picture']

            for key, informations in blockchain.Identity_contestants.items():
                if any(candidate['private_key'] == private_key for candidate in informations):
                    flash("Already existing candidate")
                    return render_template('candidateManagement.html')

            picture_name = secure_filename(picture.filename)
            picture_path = os.path.join(os.path.join(app.root_path, 'static/uploads'), picture_name)
            picture.save(picture_path)

            key = Blockchain.generateAddress(Blockchain.generatePrivateKey())
            blockchain.Identity_contestants[key] = []
            blockchain.Identity_contestants[key].append({
                'private_key': private_key,
                'name': name,
                'party': party,
                'picture_name': picture_name,
                'picture_path': picture_path,
                'vot': 0
            })

            flash("Candidate added")
            Blockchain.save_data( blockchain.Identity_contestants, "contestants.json")

    else:
        return redirect(url_for('login'))
    return render_template('candidateManagement.html')


@app.route('/candidateManagement', methods = ['GET'])
def candidateManagement():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")
        print(blockchain.Identity_dict)
        return render_template('candidateManagement.html')

    else:
        return redirect(url_for('login'))
    
@app.route('/distribute_votes', methods=['GET', 'POST'])
def distributeVotes():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")

        # Actualizează voturile pentru administratori
        for admin_data in blockchain.Identity_admin[user]:
            admin_data["vot"] = len(blockchain.Identity_dict)*2

        # Create a copy of the keys to avoid "dictionary changed size during iteration" error
        dict_keys = list(blockchain.Identity_dict.keys())

        # Distribuie voturile în funcție de criterii
        for key in dict_keys:
            for person in blockchain.Identity_dict[key]:
                # Initialize "vot" as a list if it doesn't exist
                person["vot"] = person.get("vot", 0)

                if (
                    person["residence"] == "Yes"
                    and person["alienated"] == "No"
                    and person["criminal_records"] == "clean"
                ):
                    # Adaugă tranzacție doar dacă criteriile sunt îndeplinite
                    value = 1
                    if value == 1:
                        blockchain.add_transaction(blockchain.Identity_admin[user][0]['public_key'], person["public_key"], value, user)
                    else:
                        blockchain.decrease_balance(user, 1)

        flash("The votes have been distributed")
        blockchain.votes_distributed = 1
        Blockchain.save_data( blockchain.votes_distributed, "distribute_votes.json")
        print(blockchain.votes_distributed)
        print(blockchain.Identity_dict)
        return voterManagement()
    else:
        return redirect(url_for('login'))
 
@app.route('/voterManagement', methods = ['GET', 'POST'])
def voterManagement():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_admin[user][0]['nume']}", "error")
        if blockchain.votes_distributed == 1:
            flash("Votes are distributed")
        else: 
            flash("Votes are not distributed")
        identity_dict = blockchain.Identity_dict
        return render_template('voterManagement.html', identity_dict = identity_dict)

    else:
        return redirect(url_for('login'))
## voteeeeeeeeeeeeeee
@app.route('/vote', methods = ['GET', 'POST'])
def vote():
    if "user" in session:
        if is_voting_period(blockchain.voting_start_date, blockchain.voting_end_date):
            if blockchain.votes_distributed == 1:    
                user = session["user"]
                flash(f"{blockchain.Identity_dict[user][0]['name']}", "error")
                flash(f"{blockchain.Identity_dict[user][0]['vot']}", "error")
                flash(f"Ai votat cu succes")
                private_key_candidate = request.form.get('my_variable')
                blockchain.add_transaction(blockchain.Identity_dict[user][0]['public_key'], private_key_candidate, 1, blockchain.Identity_dict[user][0]['private_key'])
                return render_template('userPage.html', identity_contestants=blockchain.Identity_contestants, start_vote = blockchain.voting_start_date, end_vote = blockchain.voting_end_date)
            else:
                flash(f"{blockchain.Identity_dict[user][0]['name']}", "error")
                flash(f"{blockchain.Identity_dict[user][0]['vot']}", "error")
                flash("Votes are not distributed, please contact the institution")
                return render_template('userPage.html', identity_contestants=blockchain.Identity_contestants, start_vote = blockchain.voting_start_date, end_vote = blockchain.voting_end_date)                
        else:
            return render_template('userPage.html')
    else:
        return redirect(url_for('login'))    

@app.route('/userPage')
def userPage():
    if "user" in session:
        user = session["user"]
        flash(f"{blockchain.Identity_dict[user][0]['name']}", "error")
        if is_voting_period(blockchain.voting_start_date, blockchain.voting_end_date): 
            return render_template('userPage.html', identity_contestants=blockchain.Identity_contestants, start_vote = blockchain.voting_start_date, end_vote = blockchain.voting_end_date)   
        else:
            flash(f"There is not a vote active right now")
            return redirect(url_for('finalResults'))
    else:
        return redirect(url_for('login'))

@app.route('/create_account', methods=['GET', 'POST'])
def create_account():
    if request.method == 'POST':
        private_key = request.form.get('private_key')
        password = request.form.get('password')
        confirmPassword = request.form.get('confirm_password')

        # Verifică dacă cheia privată este deja în uz
        if private_key not in blockchain.Identity_dict and private_key not in blockchain.Identity_admin:
            flash("The Private Key is wrong", "error")
            return render_template('create.html')

        # Verifică dacă parola este prea scurtă
        if len(password) < 10:
            flash("Password is too short, please enter at least 10 characters", "error")
            return render_template('create.html')

        # Verifică dacă parolele corespund
        if password != confirmPassword:
            flash("Passwords do not match, check your passwords", "error")
            return render_template('create.html')

        # Dacă nu există erori, creează un cont nou
        blockchain.Users[private_key] = Blockchain.hash_password(password)
        Blockchain.save_data(blockchain.Users, "credentials_block.json")


        # Crează un fișier text cu cheia privată și parola
        filename = f"{secure_filename(blockchain.Identity_dict[private_key][0]['name'])}_credentials.txt"
        file_path = os.path.join("c:\\Users\\florin.chivari\\Desktop\\CC\\Licenta2-cc", filename)
        with open(file_path, 'w') as f:
            f.write(f"Private Key: {private_key}\n")
            f.write(f"Password: {password}\n")

        @after_this_request
        def remove_file(response):
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Error removing file: {e}")
            return response

        # Trimite fișierul utilizatorului
        send_file(file_path, as_attachment=True)

    return render_template('create.html')

#i need to send a email that the request was suscesfully
@app.route('/obtain_private_key', methods=['GET', 'POST'])
def obtain_private_key():
    if request.method == 'POST':
        
        if request.method == 'POST':
            name = request.form.get('name')
            date_of_birth = request.form.get('date_of_birth')
            CNP = request.form.get('CNP')
            nationality = request.form.get('nationality')
            criminal_record = request.form.get('criminal_record')
            email = request.form.get('email')
            identity_document = request.files['identity_document']
            criminal_record_document = request.files['criminal_record_document']

            print(request.files)
            # Create a folder for the user if it doesn't exist
            user_folder = os.path.join(app.root_path, 'static/uploads', CNP)
            os.makedirs(user_folder, exist_ok=True)

            # Save identity document
            if identity_document:
                id_name = secure_filename(identity_document.filename)
                id_path = os.path.join(user_folder, id_name)
                identity_document.save(id_path)

            # Save criminal record document
            if criminal_record_document:
                criminal_record_doc_name = secure_filename(criminal_record_document.filename)
                criminal_record_doc_path = os.path.join(user_folder, criminal_record_doc_name)
                criminal_record_document.save(criminal_record_doc_path)
        blockchain.ToBeDetermined[CNP]= []
        blockchain.ToBeDetermined[CNP].append({
                'email': email,
                'name': name,
                'date_of_birth': date_of_birth,
                'nationality': nationality,
                'criminal_record': criminal_record,
                'criminal_record_doc_name': criminal_record_doc_name,
                'criminal_record_doc_path': criminal_record_doc_path,
                'identity_document': identity_document,
                'id_name': id_name,
                'id_path': id_path,
            })
        print(blockchain.ToBeDetermined)

        return redirect(url_for('index'))
    return render_template('register2PrivKey.html')

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for('index'))

@app.route('/viewLedger', methods=['GET'])
def viewLedger():
 # Get the current page number from the request, default to 1 if not specified
    page = request.args.get('page', 1, type=int)
    
    # Number of blocks per page
    blocks_per_page = 10
    
    # Reverse the chain to display from newest to oldest
    reversed_chain = blockchain.chain[::-1]
    
    # Calculate the start and end indices for the blocks to display on this page
    start = (page - 1) * blocks_per_page
    end = start + blocks_per_page
    
    # Get the blocks for the current page
    blocks = reversed_chain[start:end]
    print(blockchain.chain)
    
    # Calculate the total number of pages
    total_pages = (len(blockchain.chain) + blocks_per_page - 1) // blocks_per_page
    
    return render_template('viewLedger.html', block=blockchain.chain, page=page, total_pages=total_pages)




@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(proof, previous_hash)
    response = {'message': 'Congratulations, you just mined a block!',
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash'],
                'transactions': block['transactions']}
    return jsonify(response), 200

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    json_data = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount', 'private_key']
    if not all(key in json_data for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400
    result = blockchain.add_transaction(json_data['sender'], json_data['receiver'], json_data['amount'], json_data['private_key'])
    if result:
        blockchain.broadcast_transaction(json_data)
        response = {'message': 'Transaction added and broadcasted successfully'}
    else:
        response = {'message': 'Insufficient balance or invalid transaction'}
    return jsonify(response), 201

@app.route('/add_block', methods=['POST'])
def add_block():
    json_data = request.get_json()
    block = json_data
    previous_block = blockchain.get_previous_block()
    if previous_block['hash'] == block['previous_hash'] and blockchain.is_chain_valid(blockchain.chain + [block]):
        blockchain.chain.append(block)
        blockchain.broadcast_block(block)
        response = {'message': 'Block added and broadcasted successfully'}
    else:
        response = {'message': 'Block rejected'}
    return jsonify(response), 201

@app.route('/connect', methods=['POST'])
def connect_node():
    json_data = request.get_json()
    node_address = json_data.get('node_address')
    if node_address is None:
        return 'No node address provided', 400
    host, port = node_address.split(':')
    blockchain.connect_to_peer(host, int(port))
    response = {'message': f'Connected to node {node_address}'}
    return jsonify(response), 200

@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    is_chain_replaced = blockchain.sync_chain()
    if is_chain_replaced:
        response = {
            'message': 'The nodes had different chains so the chain was replaced by the longest one.',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'All good. The chain is the largest one.',
            'actual_chain': blockchain.chain
        }
    return jsonify(response), 200

@app.route('/chain', methods=['GET'])
def get_chain():
    response = {'chain': blockchain.chain, 'length': len(blockchain.chain)}
    return jsonify(response), 200

if __name__ == '__main__':
    blockchain = Blockchain()
    app.run(host='0.0.0.0', port=5000)

