from django.shortcuts import render

# Create your views here.
from django.http import HttpResponseRedirect

from hcaptcha.fields import hCaptchaField
from django import forms

import os
from ratelimit.decorators import ratelimit
from ratelimit.core import get_usage

class Forms(forms.Form):
    hcaptcha = hCaptchaField()
    address = forms.CharField(label='', max_length=100, widget=forms.TextInput(attrs={'placeholder': 'Your MurraxCoin address'}))


def index(request):
    # if this is a POST request we need to process the form data
    if request.method == 'POST':
        limited = get_usage(request, key="ip", method=["GET", "POST"], fn=index, increment=True, rate="1/d")
        if limited["count"] > limited["limit"]:
            return HttpResponseRedirect("/mxc_faucet/claimed")
        # create a form instance and populate it with data from the request:
        form = Forms(request.POST)
        # check whether it's valid:
        if form.is_valid():
            # process the data in form.cleaned_data as required
            # ...
            # redirect to a new URL:
            print(form.cleaned_data["address"])
            print(os.listdir())
            return HttpResponseRedirect('/mxc_faucet/claimed')

    #  if a GET (or any other method) we'll create a blank form
    else:
        limited = get_usage(request, key="ip", method=["GET", "POST"], increment=False, fn=index, rate="1/d")
        if limited["count"] >= limited["limit"]:
            return HttpResponseRedirect("/mxc_faucet/claimed")

        form = Forms()

    return render(request, 'name.html', {'form': form})


def claimed(request):
    return render(request, "claimed.html")