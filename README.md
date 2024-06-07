# P2p secure chat communication
<pre>
<h3>1.User registration and authentication.
2.RSA key generation for message signing and verification.
3.SQLite database for storing user credentials.
4.Peer-to-peer chat functionality.

<h2>#Exicuting the process</h2>
a.Installation of Necessary Libraries
  1.Standard Libraries:socket, threading, sqlite3, and hashlib
  2.Third-Party Libraries:cryptography
b.Initialize the Database(python initialize_db.py)
c.Register users in database (python user_registration.py)
d.Authenticate with the username and password you registered earlier(python user_authentication.py)
e.Start the Chat Application:Start two instances of your chat application. One will listen on a port, and the other will connect to it.
     example
    .In the first terminal, run:python chatApp.py 12345
    .In the secondt terminal,run:python chatApp.py 12346 127.0.0.1 12345
</h3>
    </pre>
