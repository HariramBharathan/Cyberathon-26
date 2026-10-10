from urllib.parse import urlparse

from flask import Blueprint, g, redirect, render_template, request, url_for

from ..services.session_service import page_login_required

web = Blueprint("web", __name__)


@web.get("/")
def landing():
    if g.get("user"):
        return redirect(url_for("web.application"))
    return render_template("landing.html")


@web.get("/login")
def login():
    if g.get("user"):
        return redirect(url_for("web.application"))
    target = request.args.get("next", "")
    if target and (urlparse(target).netloc or not target.startswith("/")):
        target = ""
    return render_template("auth.html", mode="login", next_url=target)


@web.get("/register")
def register_page():
    if g.get("user"):
        return redirect(url_for("web.application"))
    return render_template("auth.html", mode="register", next_url="")


@web.get("/app")
@page_login_required
def application():
    return render_template("dashboard.html")


@web.get("/approve/<request_id>")
def approve_page(request_id):
    return render_template("approve.html", request_id=request_id)