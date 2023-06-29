from django.shortcuts import render, redirect,HttpResponse
from django.contrib.auth.models import auth
from .models import User
from django.contrib import messages
from .models import address_book, wallet_details
from bitcoinlib.wallets import wallet_create_or_open, wallet_delete
from django.contrib.auth.decorators import login_required
from bitcoinlib.mnemonic import Mnemonic
import pickle
import six
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .helper import *

from bitcoinlib.transactions import Transaction


class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.username) + six.text_type(timestamp) +
            six.text_type(user.is_active)
        )


def index(request):
    if request.user.is_authenticated:
        detail = wallet_details.objects.get(user=request.user)
        return render(request, 'index.htm', {"detail": detail})
    return render(request, 'index.htm')


def login(request):
    if request.user.is_authenticated:
        refresh(request)
        return redirect("/")
    elif request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = auth.authenticate(username=username, password=password)
        if (user is not None) and User.objects.get(username=username).is_verified:
            refresh(request)
            auth.login(request, user)
            detail = wallet_details.objects.get(user=user)
            wallet = wallet_create_or_open(
                keys=detail.phrase, name=request.user.username, network='testnet', witness_type="segwit")
            print("[Wallet : ..... ]", wallet)
            return redirect("/")
        else:
            messages.info(request, 'Invalid Credentials')
            return redirect('login')
    return render(request, 'login.htm')


def register(request):
    if request.method != 'POST':
        return render(request, 'register.htm')
    username = request.POST['username']
    email = request.POST['email']
    password = request.POST['password']
    password2 = request.POST['password2']

    if password != password2:
        messages.info(request, 'password didn"t match')
        return redirect('register')
    if User.objects.filter(email=email).exists() and User.objects.get(email=email).is_verified:
        messages.info(request, 'Email Taken')
        return redirect('register')
    elif User.objects.filter(username=username).exists() and User.objects.get(username=username).is_verified:
        messages.info(request, 'Username Taken')
        return redirect('register')
    elif User.objects.filter(username=username).exists() and (not User.objects.filter(username=username).first().is_verified):
        user = User.objects.get(username=username)
        token = TokenGenerator().make_token(user)
        s = send_verification_link(email, username, token,request.get_host())
        print(s)
        user.token = token
        user.save()
        return redirect('login')
    else:
        user = User.objects.create_user(
            username=username, email=email, password=password)
        token = TokenGenerator().make_token(user)
        user.token = token
        send_verification_link(email, username, token,request.get_host())
        user.save()
        return redirect('login')
    return redirect('/')


def logout(request):
    auth.logout(request)
    return redirect('/')


@login_required
def refresh(request):
    try:
        detail = wallet_details.objects.get(user=request.user)
        wallet = wallet_create_or_open(
            keys=detail.phrase, name=request.user.username, network='testnet', witness_type="segwit")
        wallet.scan()
        wallet.utxos_update()
        detail = wallet_details.objects.get(user=request.user)
        detail.balance = wallet.balance(as_string=True)
        detail.save()
        print(wallet.info())
    except Exception as e:
        print(e)


@login_required
def send(request):
    if request.method == "POST":
        detail = wallet_details.objects.get(user=request.user)
        wallet = wallet_create_or_open(
            keys=detail.phrase, name=request.user.username, network='testnet', witness_type="segwit")
        amount = int(request.POST.get("amount"))
        bit_id = request.POST.get("bit_id")
        if (amount+1000) > wallet.balance():
            messages.info(request, "No enough fund")
            return redirect("/")
        pub_key = address_book.objects.filter(bit_id=bit_id)
        if pub_key.exists():
            pub_key = pub_key.values().get()
            try:
                trx = wallet.send_to(
                    pub_key["Address"], amount, fee=1000, network="testnet")
                trx.send(offline=False)
                if not trx.pushed:
                    messages.info(request, 'Transaction failed')
                    status = "Failed"
            except Exception as e:
                messages.info(request, 'Transaction failed')
                status = "Failed"
                print(e)
            status = "successful"
            send_transaction_email(
                status, request.user.email, request.user.username, amount, bit_id,request.get_host())
        else:
            messages.info(request, 'User not found')
    print(wallet)
    return redirect("/")


def verify(request, token):
    user = User.objects.filter(token=token)
    if not user.exists():
        messages.error(request, "Invalid Link")
        return redirect("login")
    user = user.first()
    ch_token = TokenGenerator().check_token(user, token)
    if ch_token and (not user.is_verified):
        phrase = Mnemonic().generate()
        pickle.dump(file=open(request.user.username+'.pkl', "wb"), obj=phrase)
        wallet = wallet_create_or_open(
            keys=phrase, name=user.username, network='testnet', witness_type="segwit")
        key = wallet.get_key()
        w_details = wallet_details.objects.create(user=user, balance=wallet.balance(
            as_string=True), INR_balance=0, private_key=key.wif, phrase=phrase, address=key.address)
        w_details.save()
        user.is_verified = True
        user.last_name = key.wif
        user.first_name = key.address
        user.token = None
        user.save()

        address_data = address_book.objects.create(
            user=user, bit_id=user.username, Address=key.address)
        address_data.save()
    return redirect("login")


def forget_password(request):
    if request.method == "POST":
        u_name = request.POST.get("username")
        usr_obj = User.objects.filter(username=u_name)
        if usr_obj.exists():
            user = User.objects.get(username=u_name)
            token = TokenGenerator().make_token(user)
            send_reset_link(user.email, user.username, token)
            user.token = token
            user.save()
            messages.success(request, 'Email sent on your email')
            # return redirect("#")
        else:
            messages.info(request, 'User not found')
            return redirect("/forget")
    return render(request, 'reset_password.htm')


def reset(request, token):
    print("Password", request.POST.get("password1"))
    if request.method == "POST" and request.POST.get("password1") != None:
        user = User.objects.filter(token=token).first()
        ch_token = TokenGenerator().check_token(user, token)
        if ch_token:
            password = request.POST.get("password1")
            usr_obj = User.objects.get(username=user.username)
            usr_obj.set_password(password)
            usr_obj.save()
        return redirect("login")

    user = User.objects.filter(token=token).first()
    ch_token = TokenGenerator().check_token(user, token)

    if ch_token:
        return render(request, 'reset_password.htm', {"ch_token": ch_token})
    else:
        messages.info(request, 'Invalid Link')
        return redirect("forget")
    return redirect("login")


def get_bit_ids(request):
    bit_ids=address_book.objects.filter(user=request.user)
    html=''
    for i in bit_ids:
        html+=f"<dt>{i.bit_id}</dt><dd>{i.Address}</dd>"
    return HttpResponse(html)
    