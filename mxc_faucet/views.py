from django.shortcuts import render

# Create your views here.
from django.http import HttpResponseRedirect

from hcaptcha.fields import hCaptchaField
from django import forms



import asyncio
import json
from datetime import datetime
from datetime import timedelta

# MurraxCoin imports
import websockets
import os
from Crypto.PublicKey import ECC
from Crypto.Hash import BLAKE2b
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from nacl.signing import SigningKey

import base64
import zlib

privateFile = "private/genesis.pem"
publicFile = "private/public_key.pem"
handshakeFile = "private/handshake_key.pem"

try:
    f = open(handshakeFile, "rb")
    handshakeKey = RSA.import_key(f.read())
    f.close()

except FileNotFoundError:
    handshakeKey = RSA.generate(2048)
    toWrite = handshakeKey.export_key()
    f = open(handshakeFile, "wb+")
    f.write(toWrite)
    f.close()
    del toWrite

handshakePublicKey = handshakeKey.publickey()
handshakePublicKeyStr = handshakePublicKey.export_key()
handshakeCipher = PKCS1_OAEP.new(handshakeKey)

try:
    f = open(privateFile, "rb")
    privateKey = SigningKey(f.read())
    f.close()

except:
    seed = os.urandom(32)
    privateKey = SigningKey(seed)
    f = open(privateFile, "wb+")
    f.write(seed)
    f.close()

publicKey = privateKey.verify_key

addressChecksum = zlib.adler32(publicKey.encode()).to_bytes(4, byteorder="big")
addressChecksum = base64.b32encode(addressChecksum).decode("utf-8").replace("=", "").lower()
address = base64.b32encode(publicKey.encode()).decode("utf-8").replace("=", "").lower()
publicKeyStr = f"mxc_{address}{addressChecksum}"

class websocketSecure:
    def __init__(self, url):
        self.url = url

    async def initiateConnection(self):
        self.websocket = await websockets.connect(self.url)
        await self.websocket.send(handshakePublicKeyStr)
        handshakeData = await self.websocket.recv()
        handshakeData = json.loads(handshakeData)

        sessionKey = base64.b64decode(handshakeData["sessionKey"].encode('utf-8'))
        #sessionKey = bytes.fromhex(handshakeData["sessionKey"])
        self.sessionKey = handshakeCipher.decrypt(sessionKey)

    @classmethod
    async def connect(cls, url):
        self = websocketSecure(url)
        await asyncio.wait({self.initiateConnection()})
        for i in range(200):
            try:
                self.sessionKey
                return self

            except:
                await asyncio.sleep(0.1)

        raise TimeoutError


    async def recv(self):
        data = await self.websocket.recv()
        ciphertext, tag, nonce = data.split("|||")
        ciphertext, tag, nonce = base64.b64decode(ciphertext.encode("utf-8")), base64.b64decode(tag), base64.b64decode(nonce)
        cipher = AES.new(self.sessionKey, AES.MODE_GCM, nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        plaintext = plaintext.decode("utf-8")

        return plaintext

    async def send(self, plaintext):
        cipher = AES.new(self.sessionKey, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
        await self.websocket.send(base64.b64encode(ciphertext).decode("utf-8") + "|||" + base64.b64encode(tag).decode("utf-8") + "|||" + base64.b64encode(cipher.nonce).decode("utf-8"))


    async def close(self):
        await self.websocket.close()


async def genSignature(data, privateKey):
    data = json.dumps(data).encode()
    signature = privateKey.sign(data).signature
    signature = hex(int.from_bytes(signature, "little"))

    return signature

websocket = None


async def ping():
    await websocket.send('{"type": "ping"}')
    resp = await websocket.recv()
    return resp

uri = "ws://murraxcoin.murraygrov.es:6969"
websocket = None


def get_ip_address(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def checkAllowed(request):
    try:
        f = open("private/fingerprints.json")
        data = f.read()
        f.close()
        data = json.loads(data)

    except:
        data = {}

    fingerprint = get_ip_address(request)
    if fingerprint not in data:
        allowed = True

    else:
        nextAllowed = datetime.strptime(data[fingerprint], "%y/%m/%d %H:%M:%S")
        allowed = True if datetime.now() > nextAllowed else False

    if allowed and request.method == "POST":
        newAllowed = datetime.now() + timedelta(days=1)
        nextAllowed = newAllowed.strftime("%y/%m/%d %H:%M:%S")

        data[fingerprint] = nextAllowed
        data = json.dumps(data)

        f = open("private/fingerprints.json", "w+")
        f.write(data)
        f.close()

    return allowed

websocket = False

class Forms(forms.Form):
    hcaptcha = hCaptchaField()
    address = forms.CharField(label='', max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Your MurraxCoin address'}))


async def sendMxc(address):
    websocket = await websocketSecure.connect(uri)

    await websocket.send(f'{{"type": "balance", "address": "{publicKeyStr}"}}')
    resp = await websocket.recv()
    resp = json.loads(resp)
    balance = float(resp["balance"])

    toSend = balance * 0.0001
    newBalance = balance-toSend

    await websocket.send(f'{{"type": "getPrevious", "address": "{publicKeyStr}"}}')
    response = await websocket.recv()
    previous = json.loads(response)["link"]

    await websocket.send(json.dumps({"type": "getRepresentative", "address": publicKeyStr}))
    response = await websocket.recv()
    representative = json.loads(response)["representative"]

    data = {"type": "send", "address": f"{publicKeyStr}", "link": f"{address}", "balance": f"{newBalance}",
            "previous": previous, "representative": representative}

    hasher = BLAKE2b.new(digest_bits=512)
    blockID = hasher.update(json.dumps(data).encode()).hexdigest()
    data["id"] = blockID

    signature = await genSignature(data, privateKey)
    data = {**data, **{"signature": f"{signature}"}}
    await websocket.send(json.dumps(data))
    resp = await websocket.recv()
    if json.loads(resp)["type"] == "confirm":
        print("MXC send initiated!")
        print("SENT:", address)

    else:
        print("MXC send failed to initiate, please see error below:")
        print(resp)

    await websocket.close()



def index(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = Forms(request.POST)
        # check whether it's valid:
        validForm = form.is_valid()
        if not validForm:
            return HttpResponseRedirect("/mxc_faucet/invalidcaptcha")

        elif checkAllowed(request):
            # process the data in form.cleaned_data as required
            # ...
            # redirect to a new URL:
            address = form.cleaned_data["address"]
            try:
                loop = asyncio.get_event_loop()

            except:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            loop.run_until_complete(sendMxc(address))

            return HttpResponseRedirect('/mxc_faucet/claimed')

        else:
            return HttpResponseRedirect("/mxc_faucet/forbidden")


    #  if a GET (or any other method) we'll create a blank form
    else:
        form = Forms()

    return render(request, 'name.html', {'form': form})


def claimed(request):
    return render(request, "claimed.html")


def forbidden(request):
    return render(request, "forbidden.html")

def invalidcaptcha(request):
    return render(request, "invalidcaptcha.html")
