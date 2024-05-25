import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
import os
import random
from blockchain import Blockchain

class Wallet:



    def generateAddress(private_Key):       #generation of the public and private addresses and they conversion in txt format
        public_key = hashlib.sha256(private_Key.encode()).hexdigest()
        return public_key
    
    def generatePrivateKey():       #generation of the public and private addresses and they conversion in txt format
        private_Key = hashlib.sha256(os.urandom(64)).hexdigest()
        print("private key", private_Key)
        return private_Key
    



    

    


        

