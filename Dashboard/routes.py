import json
import os
import re
import subprocess
import threading
import time
from datetime import datetime
import socket

import requests
import schedule

from Dashboard import app
from flask import Flask, render_template, request, redirect, session, url_for, jsonify

# Define Downloaded variables
AUTHENTICATION = SIGLENT = COMMAND = None

# Define Local variables
HOME_PATH = USER_TIMER = SCREEN_HEIGHT = USER_ALARM = USER_NAME = WIFI_DRIVER_NAME = \
    PATH_POST = AUTH_KEY = SIGLENT_CONNECTION = ""
ONCE_INDEX = False
Profile_filePath = os.path.dirname(os.path.abspath(__file__)) + "/Profile/profile_save.json"


def load__profile():  # only called once, afterwards authentication thread and dl + save settings takes
    global HOME_PATH, PATH_POST, USER_NAME, AUTH_KEY, WIFI_DRIVER_NAME, \
        USER_TIMER, USER_ALARM, SCREEN_HEIGHT
    #  Load Variables from Profile
    HOME_PATH = readJsonValueFromKey("HOME_PATH", Profile_filePath)
    AUTH_KEY = readJsonValueFromKey("AUTH_KEY", Profile_filePath)
    PATH_POST = readJsonValueFromKey("PATH_POST", Profile_filePath)
    USER_NAME = readJsonValueFromKey("USER_NAME", Profile_filePath)
    USER_TIMER = readJsonValueFromKey("USER_TIMER", Profile_filePath)
    USER_ALARM = readJsonValueFromKey("USER_ALARM", Profile_filePath)
    SCREEN_HEIGHT = readJsonValueFromKey("SCREEN_HEIGHT", Profile_filePath)
    WIFI_DRIVER_NAME = readJsonValueFromKey("WIFI_DRIVER_NAME", Profile_filePath)


def download_profile():
    # Download profile and load all profile/global variables
    global AUTHENTICATION, SIGLENT, COMMAND, AUTH_KEY, PATH_POST

    # Set default profile data
    profileData = {'authenticated': 0, 'siglent': 0, 'command': 0}

    # Send POST request and parse JSON response
    try:
        dict_to_send = {'auth_key': AUTH_KEY, 'GET': {'Request': 'Profile'}}
        headers = {'Content-type': 'application/json'}
        res = requests.post(url=PATH_POST, json=dict_to_send, headers=headers)
        profileData = res.json()
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', f'Profile POST error, this confirms POST is working. {error}')

    # Extract values from JSON response
    AUTHENTICATION = profileData['authenticated']
    SIGLENT = profileData['siglent']
    COMMAND = profileData['command']
    print("Auth: " + str(AUTHENTICATION) + " Siglent: " + str(SIGLENT) + " Command: " + str(COMMAND))


def Siglent_SocketConnect():
    global SIGLENT_CONNECTION
    try:
        # create an AF_INET, STREAM socket (TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('Failed to create socket.')
        SIGLENT_CONNECTION = ""
    try:
        # Connect to remote server
        s.connect((SIGLENT_CONNECTION, 5024))
    except socket.error:
        print('failed to connect to ip ' + SIGLENT_CONNECTION)
        SIGLENT_CONNECTION = ""
    return s


def Siglent_SocketSend(Sock, cmd):
    global SIGLENT_CONNECTION
    try:
        # Send cmd string
        Sock.sendall(cmd)
        Sock.sendall(b'\n')
        time.sleep(0.4)
    except socket.error:
        # Send failed
        print('Send failed')
        SIGLENT_CONNECTION = ""
    # reply = Sock.recv(4096)
    # return reply


def Siglent_SocketClose(Sock):
    Sock.close()
    time.sleep(0.4)


def ON():
    try:
        s = Siglent_SocketConnect()
        Siglent_SocketSend(s, b'C2:OUTP ON')  # Set CH1 ON
        Siglent_SocketSend(s, b'C1:OUTP ON')  # test
        Siglent_SocketClose(s)  # Close socket
    except Exception as error:
        return error.__str__()


def OFF():
    try:
        s = Siglent_SocketConnect()
        Siglent_SocketSend(s, b'C2:OUTP OFF')
        Siglent_SocketSend(s, b'C1:OUTP OFF')
        Siglent_SocketClose(s)  # Close socket
        return 'Query complete.'
    except Exception as error:
        return error.__str__()


is_running = False
processing = False


def signal_gen_controller(mode):
    global SIGLENT, is_running, processing
    # Control signal generator
    if not SIGLENT == 1:  # Signal Gen is knockoff
        if not processing:
            if mode == "ON":
                if not is_running:
                    # processing true
                    processing = True
                    #  MHS5200 SIGNAL
                    os.system(
                        'sudo ' + HOME_PATH +
                        'MHS-5200-Driver/mhs5200 /dev/ttyUSB0 channel 1 arb 0 amplitude 4 freq 364 on')
                    time.sleep(.4)
                    is_running = True
                    processing = False
            if mode == "OFF":
                if is_running:
                    processing = True
                    #  MHS5200 SIGNAL
                    os.system(
                        'sudo ' + HOME_PATH +
                        'MHS-5200-Driver/mhs5200 /dev/ttyUSB0 channel 1 arb 0 amplitude 4 freq 364 off')
                    time.sleep(.4)
                    is_running = False
                    processing = False
    # Siglent - Expensive
    if not processing:
        if mode == "ON":
            if not is_running:
                processing = True
                pass  # do work
                # Turn siglent signal
                try:
                    ON()
                except Exception as error:
                    # add exceptions to mode
                    send_statistic('ACTIVE_UPDATE', 'Siglent ON failed: ' + error.__str__())
                    return error.__str__()
                processing = False
        if mode == "OFF":
            if is_running:
                processing = True
                pass  # do work
                # Turn siglent signal
                try:
                    ON()
                except Exception as error:
                    # add exceptions to mode
                    send_statistic('ACTIVE_UPDATE', 'Siglent OFF failed: ' + error.__str__())
                processing = False


def amp_controller(mode):
    try:
        if mode == "ON":
            # GPIO 91 0 AMP ON
            os.system('sudo gpioset 1 91=0')
        elif mode == "OFF":
            # GPIO 91 1 AMP OFF
            os.system('sudo gpioset 1 91=1')
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'power_supply_amp_ Error ' + str(error))


def extension_power_controller(mode):
    # Used for siglent
    try:
        if mode == "ON":
            # GPIO 92 0 extension_power ON
            os.system('sudo gpioset 1 92=0')
        elif mode == "OFF":
            # GPIO 92 1 extension_power OFF
            os.system('sudo gpioset 1 92=1')
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'power_supply_amp_ Error ' + str(error))


def tube1tube2_controller(mode):
    # GPIO output to Tube 1 and 2
    try:
        if mode == "ON":
            # GPIO 93+94 0 TUBE ON
            os.system('sudo gpioset 1 93=0')
            os.system('sudo gpioset 1 94=0')
        elif mode == "OFF":
            # GPIO 93+94 1 TUBE OFF
            os.system('sudo gpioset 1 93=1')
            os.system('sudo gpioset 1 94=1')
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'tube Error ' + str(error))
    pass


def is_user_authorized():
    # Check if user is authorized based on profile
    try:
        global AUTHENTICATION
        print("User Authentication check")
        if AUTHENTICATION == 1:
            print("Pass")
            return True
        else:
            print("FAIL")
            return False
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'isUserAuthorized() failed. ' + str(error))


def wifi_check():
    # Perform WiFi check and return True or False
    print("internet check")
    try:
        req = requests.get('http://clients3.google.com/generate_204')
        if req.status_code != 204:
            req = requests.get('http://google.com/')
            if req != 200:
                return False
            else:  # double check
                return True
        else:
            return True
    except Exception as error:
        print("internet issue" + error.__str__())
        return False


def send_statistic(statistic, value):
    # Send - Web Server
    global PATH_POST, AUTH_KEY
    try:
        dictToSend = {'auth_key': AUTH_KEY,
                      'Analytics': {statistic: value}}
        headers = {'Content-type': 'application/json'}
        requests.post(url=PATH_POST, json=dictToSend, headers=headers)
    except Exception as error:
        print('send_statistic failed: ' + str('statistic: ' + statistic) +
              str('value: ' + value) + str(error))


def get_my_public_ip():
    # Get public IP address
    try:
        endpoint = 'https://ipinfo.io/json'
        response = requests.get(endpoint, verify=True)
        if response.status_code != 200:
            return 'Status:', response.status_code, 'Problem with the request. Exiting.'
        data = response.json()
        return data['ip']
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'getMyPublicIP() failed. ' + str(error))


def run_command():
    # Run command
    print("checking command")
    global COMMAND
    print(COMMAND)
    if COMMAND != '0':
        # reply with the subprocess might be cool
        print("command ran")
        try:
            response = subprocess.check_output(str(COMMAND), shell=True)
            send_statistic('ACTIVE_UPDATE', "COMMAND RESPONSE: " + response.decode("utf-8"))
            send_statistic('command', '0')
        except subprocess.CalledProcessError as err:
            send_statistic('ACTIVE_UPDATE', str(err))


def getLocalIP():
    try:
        response = subprocess.check_output('hostname -I', shell=True)
        return str(response.decode("utf-8")) + ':5000'
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'get_ip failed: ' + str(error))


def updateJsonFile(Key, Value, filePath):
    try:
        jsonFile = open(filePath, "r")
        data = json.load(jsonFile)  # Read the JSON into the buffer
        jsonFile.close()
        # Update Key & Value
        data[Key] = Value
        # Save changes to JSON file
        jsonFile = open(filePath, "w+")
        jsonFile.write(json.dumps(data))
        jsonFile.close()
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'updateJsonFile() failed. ' + str(filePath)
                       + str('Key: ' + Key) + str('Value: ' + Value) + str(error))


def readJsonValueFromKey(Key, filePath):
    try:
        f = open(filePath)
        data = json.load(f)
        f.close()
        return data[Key]
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'readJsonValueFromKey() failed. ' + str(filePath)
                       + str('Key: ' + Key) + str(error))


def authentication_check_thread():
    # Start authentication loop thread
    try:
        total_minutes = 1
        while total_minutes > 0:
            time.sleep(60)
            total_minutes -= 1
        # after x minutes check
        if wifi_check():
            download_profile()
            if not is_user_authorized():
                return redirect(url_for('/not_authenticated'))
        else:
            return redirect(url_for('/no_wifi'))
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'BackgroundAuthCheck() Error. ' + 'ONCE_INDEX: ' + str(ONCE_INDEX) + str(error))


schedulerThread = None
authenticationThread = None
timer_job = None
alarm_job = None


def TimerAlarm_Buttons(data):
    global timer_job, alarm_job, USER_TIMER, USER_ALARM
    print(data)
    try:
        if "timerButton" in data:
            # Keep jobs clear from interfering
            if alarm_job in schedule.jobs:
                print("killed alarm")
                schedule.cancel_job(alarm_job)

            if timer_job in schedule.jobs:
                # stop timer
                print("timer stop")
                schedule.cancel_job(timer_job)
            else:
                # start timer
                print("timer start")
                print(USER_TIMER)
                timer_job = schedule.every(int(USER_TIMER)).minutes.do(timer_action)
            return jsonify({'processed': 'true'})
        if "alarmButton" in data:
            # Keep jobs clear from interfering
            if timer_job in schedule.jobs:
                print("killed timer")
                schedule.cancel_job(timer_job)

            if alarm_job in schedule.jobs:
                # stop alarm
                print("alarm stop")
                schedule.cancel_job(alarm_job)
            else:
                # start alarm
                print("alarm start")
                print(USER_ALARM)
                alarm_job = schedule.every().day.at(USER_ALARM).do(alarm_action)
            return jsonify({'processed': 'true'})
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'TimerAlarm_Buttons() Failed. ' + str(error))


def run_pending_jobs():
    while True:
        schedule.run_pending()
        time.sleep(1)


def timer_action():
    print("Timer Complete")
    if timer_job in schedule.jobs:
        schedule.cancel_job(timer_job)


def alarm_action():
    print("hello")
    if alarm_job in schedule.jobs:
        schedule.cancel_job(alarm_job)


def start_threads():
    global schedulerThread, authenticationThread
    # start the scheduler in a separate thread
    if schedulerThread is None or schedulerThread.is_alive() is False:
        schedulerThread = threading.Thread(target=run_pending_jobs)
        schedulerThread.start()
    # start the authentication check thread
    if authenticationThread is None or authenticationThread.is_alive() is False:
        authenticationThread = threading.Thread(target=authentication_check_thread)
        authenticationThread.start()


def kick_it_into_gear():
    download_profile()
    start_threads()
    run_command()
    send_statistic('IP', str(get_my_public_ip()))


@app.route('/', methods=['GET', 'POST'])
def index():
    global ONCE_INDEX, schedulerThread
    #  Load profile
    if request.method == 'GET':
        load__profile()
        if ONCE_INDEX:
            return load_index()
        elif wifi_check():
            kick_it_into_gear()
            if is_user_authorized():
                ONCE_INDEX = True
                return load_index()
            else:
                return redirect('/not_authenticated')
        else:
            return redirect('/no_wifi')
    if request.method == 'POST':
        # Handles Alarm & Timer since we use AJAX to disable/enable when done
        btn_ajax_data = request.get_json()
        return TimerAlarm_Buttons(btn_ajax_data)


@app.route('/load_index', methods=['GET'])
def load_index():
    global SCREEN_HEIGHT
    return render_template('Dashboard.html', screen_height=SCREEN_HEIGHT)


@app.route('/not_authenticated', methods=['GET'])
def not_authenticated():
    # Turn itself off? On Relay. but how would it turn on. a low voltage?
    return render_template('not_auth.html')


@app.route('/turnon')
def turnon():
    signal_gen_controller("ON")
    return "Complete"


@app.route('/turnoff')
def turnoff():
    signal_gen_controller("OFF")
    return "Complete"


@app.route('/no_wifi', methods=['GET'])
def no_wifi():
    if request.method == 'GET':
        return render_template('setup_wifi.html')
    if request.method == 'POST':
        # plug_Wifi(request.form)
        return render_template('system_reboot.html')


@app.route('/siglent_settings', methods=['GET', 'POST'])
def siglent_IP_settings():
    global SIGLENT, SIGLENT_CONNECTION
    if SIGLENT == 1:
        if request.method == 'GET':
            if not ONCE_INDEX: return index()
            return render_template("siglent_settings.html")
        if request.method == 'POST':
            # confirm IP address
            regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
            if re.search(regex, request.form['SiglentIP']):
                print("Valid Ip address")
                SIGLENT_CONNECTION = request.form['SiglentIP']
                print(SIGLENT_CONNECTION)
                return redirect(url_for('index'))
            else:
                print("Invalid Ip address")
                return render_template("siglent_settings.html", invalid="Invalid IP Address, try again.")
    else:
        return redirect(url_for('index'))


@app.route('/settings.html', methods=['GET', 'POST'])
def settings():
    # print(threading.active_count())
    if request.method == 'GET':
        if not ONCE_INDEX: return index()
        return render_template("settings.html", localIP=getLocalIP())
    if request.method == 'POST':
        data = request.form
        if 'email' in data:
            try:
                send_statistic('ACTIVE_UPDATE', data['email'])
            except Exception as error:
                send_statistic('ACTIVE_UPDATE', 'settings_send failed: email ' + 'email'
                               + str(data['email']) + str(error))
        return load_index()


@app.route('/timer_settings', methods=['GET', 'POST'])
def timer_settings():
    global timer_job, Profile_filePath, USER_TIMER
    if request.method == 'GET':
        if not ONCE_INDEX: return index()
        # Clear all Timers
        schedule.clear()
        return render_template('timer_settings.html')  # current set val
    if request.method == 'POST':
        data = request.form
        # need to check data to be an int else return
        USER_TIMER = int(data.get('set-time'))
        # update profile with new user time
        updateJsonFile('USER_TIMER', USER_TIMER, Profile_filePath)
        return load_index()


@app.route('/alarm_settings', methods=['GET', 'POST'])
def alarm_settings():
    global ONCE_INDEX, alarm_job, schedulerThread, USER_ALARM
    if request.method == 'GET':
        if not ONCE_INDEX: return index()
        # Clear all Timers
        schedule.clear()
        return render_template('alarm_settings.html')
    if request.method == 'POST':
        data = request.form
        print(data)
        # if time is not in either of these formats return, try catch return
        in_time = datetime.strptime(data.get('set-time'), "%I:%M %p")
        USER_ALARM = datetime.strftime(in_time, "%H:%M")
        # update profile with new user time
        updateJsonFile('USER_ALARM', USER_ALARM, Profile_filePath)
        return load_index()
