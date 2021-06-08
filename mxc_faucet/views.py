from django.shortcuts import render

# Create your views here.
from django.http import HttpResponseRedirect

from hcaptcha.fields import hCaptchaField
from django import forms

import os
from ratelimit.decorators import ratelimit
from ratelimit.core import get_usage
import bfa
import json
from datetime import datetime
from datetime import timedelta


def checkAllowed(request):
    try:
        f = open("private/fingerprints.json")
        data = f.read()
        f.close()
        data = json.loads(data)

    except:
        data = {}

    fingerprint = bfa.fingerprint.get(request)
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


class Forms(forms.Form):
    hcaptcha = hCaptchaField()
    address = forms.CharField(label='', max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Your MurraxCoin address'}))


def index(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        # create a form instance and populate it with data from the request:
        form = Forms(request.POST)
        # check whether it's valid:
        validForm = form.is_valid()
        if validForm and checkAllowed(request):
            # process the data in form.cleaned_data as required
            # ...
            # redirect to a new URL:
            print(form.cleaned_data["address"])
            print(os.listdir())
            return HttpResponseRedirect('/mxc_faucet/claimed')

        elif not validForm:
            return HttpResponseRedirect("/mxc_faucet/invalidcaptcha")

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