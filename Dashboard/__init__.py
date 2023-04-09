import os
import threading
import time
import json
import subprocess
from datetime import datetime, date
import requests
import re
import smtplib
import flask
import socket
import time
import sys
from flask import Flask, render_template, request, jsonify, redirect, url_for

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'

import Dashboard.service
import Dashboard.routes

