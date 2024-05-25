@app.route('/submitCandidate', methods = ['GET', 'POST'])
def submitCandidate():
    if "user" in session:
        user = session["user"]
        flash(f"{user}", "error")
        if request.method == 'POST':        
            name = request.form.get('submit_name')
            private_key = request.form.get('submit_private_key')
            party = request.form.get('political_party')
            picture = request.files['picture']  # Use square brackets, not parentheses

        if private_key not in blockchain.Identity_contestants:
            blockchain.Identity_contestants[private_key] = []

            # You can save the image to a specific folder or process it as needed
            # For example, save it to the 'uploads' folder
            picture_name = secure_filename(picture.filename)
            picture_path = os.path.join(os.path.join(app.root_path, 'static/uploads'), picture_name)
            picture.save(picture_path)

            blockchain.Identity_contestants[private_key].append({
                'public_key': Blockchain.generateAddress(Blockchain.generatePrivateKey()),
                'name': name,
                'party': party,
                'picture_name': picture_name,  # Save the image name
                'picture_path': picture_path,  # Save the image path
                'vot': 0
            })

            flash("Candidate added")
        else:
            flash("Already existing candidate")

    else:
        return redirect(url_for('login'))
    return render_template('candidateManagement.html')





##blockchain
 def start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = 5001  # Change this to a different port
        server.bind((self.host, self.port))
        server.listen(5)
        print(f"Server started on {self.host}:{self.port}")

        while True:
            conn, addr = server.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        print(f"Connection from {addr}")
        buffer = b""
        while True:
            data = conn.recv(1024)
            if not data:
                break
            buffer += data
            if b"\r\n\r\n" in buffer:
                request = buffer.decode().split("\r\n")[0]
                print(f"HTTP Request: {request}")
                buffer = b""
                if request.startswith("POST /blockchain_message"):
                    content_length = int([header.split(": ")[1] for header in buffer.decode().split("\r\n") if header.startswith("Content-Length:")][0])
                    body = buffer[-content_length:]
                    self.handle_message(body.decode())
                else:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nThis is a blockchain server.")
                    buffer = b""
        conn.close()

    def connect_to_peer(self, host, port):
        peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peer.connect((host, port))
        self.peers.append(peer)
        print(f"Connected to peer {host}:{port}")

    def broadcast(self, message):
        for peer in self.peers:
            peer.send



#app.py
threading.Thread(target=blockchain.start_server).start()









for _ in range(40):
    private_key = Blockchain.generatePrivateKey()
    name = f"Nume{_ + 41}"
    date_of_b = "1988-08-15"
    cnp = f"{random.randint(1000000000000, 9999999999999)}"
    criminal_record = random.choices(["clean", "convicted"], weights=[70, 30])[0]
    nationality_options = ["romanian", "hungarian", "german", "italian", "french"]
    nationality = random.choice(nationality_options + ["romanian"] * 3)
    residence = random.choices(["Yes", "No"], weights=[80, 20])[0]
    alienated = random.choices(["Yes", "No"], weights=[20, 80])[0]



    populate_identity_dict(private_key, name, date_of_b, cnp, criminal_record, nationality, residence, alienated)

