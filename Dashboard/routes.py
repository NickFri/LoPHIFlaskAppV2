import json, os, re, subprocess, threading, time, socket, pytz, requests, schedule, spidev
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from datetime import datetime
from Dashboard import app

# Instead of loading a web page it should just load text from metacafebliss.com
# Bring back the admin details on the settings page
# GPIO pins when gpioget changes back to default. Make sure they dont change themselves
# turn off is not disapearring
# run time zone correction
# time zone selector (can get from internet probably
# alarm set did not turn off tubes or amp/sig
# alarm didn't disable self and also flipped on tubes with sig/amp off makes no sense

# Define Downloaded variables
MESSAGE_OF_THE_DAY = AUTHENTICATION = SIGLENT = COMMAND = None

# Define Local variables
HOME_PATH = USER_TIMER = USER_ALARM = USER_NAME = WIFI_DRIVER_NAME = \
    PATH_POST = AUTH_KEY = SIGLENT_CONNECTION = "192.168.10.2"
ONCE_INDEX = False
Profile_filePath = os.path.dirname(os.path.abspath(__file__)) + "/Profile/profile_save.json"


def load__profile():  # only called once, afterwards authentication thread and dl + save settings takes
    global HOME_PATH, PATH_POST, USER_NAME, AUTH_KEY, WIFI_DRIVER_NAME, \
        USER_TIMER, USER_ALARM
    #  Load Variables from Profile
    AUTH_KEY = readJsonValueFromKey("AUTH_KEY", Profile_filePath)
    PATH_POST = readJsonValueFromKey("PATH_POST", Profile_filePath)
    USER_TIMER = readJsonValueFromKey("USER_TIMER", Profile_filePath)
    USER_ALARM = readJsonValueFromKey("USER_ALARM", Profile_filePath)
    WIFI_DRIVER_NAME = readJsonValueFromKey("WIFI_DRIVER_NAME", Profile_filePath)


temp = 2


def start_Temperature():
    global temp
    # Constants
    PERIOD_PATH = "/sys/class/pwm/pwmchip0/pwm0/period"
    DUTY_CYCLE_PATH = "/sys/class/pwm/pwmchip0/pwm0/duty_cycle"
    ENABLE_PATH = "/sys/class/pwm/pwmchip0/pwm0/enable"

    spi = spidev.SpiDev()
    spi.open(0, 0)  # Open SPI device 0, chip select 0

    def run_commandPWM(command, check=True):
        try:
            subprocess.run(command, shell=True, check=check)
        except subprocess.CalledProcessError as e:
            print(f"Command `{e.cmd}` returned with error (code {e.returncode}): {e.output}")

    def write_value(path, value):
        command = f"echo '{value}' | sudo tee '{path}' > /dev/null"
        run_commandPWM(command)

    def set_pwm_frequency_duty_cycle(frequency_hz, duty_cycle_percent):
        # Calculate period in nanoseconds from frequency in hertz
        period_ns = int((1.0 / frequency_hz) * 1e9)

        # Calculate duty cycle in nanoseconds from percentage
        duty_cycle_ns = int(period_ns * (duty_cycle_percent / 100.0))

        # Write the period and duty cycle to sysfs
        write_value(PERIOD_PATH, str(period_ns))
        write_value(DUTY_CYCLE_PATH, str(duty_cycle_ns))

    def read_temperature():
        # MAX6675 expects a 16-bit read, so we send 2 bytes and discard the first byte
        data = spi.xfer2([0, 0])
        raw_value = ((data[0] << 8) + data[1]) >> 3
        _temperature = raw_value * 0.25
        return _temperature

    try:
        # Disable PWM if it was previously enabled
        run_commandPWM("sudo /home/ubuntu/libretech-wiring-tool/ldto disable pwm-e", check=False)

        # Enable PWM
        run_commandPWM("sudo /home/ubuntu/libretech-wiring-tool/ldto enable pwm-e")

        # List PWM chips
        run_commandPWM("ls -al /sys/class/pwm")

        # Export the PWM
        write_value("/sys/class/pwm/pwmchip0/export", "0")

        while True:
            # Read the temperature
            temperature = read_temperature()
            temp = f"Temperature: {temperature} °C"

            # Adjust the fan speed based on temperature
            if temperature < 30:
                # Set low fan speed
                set_pwm_frequency_duty_cycle(frequency_hz=1000, duty_cycle_percent=30)
            elif 30 <= temperature < 60:
                # Set medium fan speed
                set_pwm_frequency_duty_cycle(frequency_hz=1000, duty_cycle_percent=60)
            else:
                # Set high fan speed
                set_pwm_frequency_duty_cycle(frequency_hz=1000, duty_cycle_percent=97)
                # 60 c and the amp should turn off
                signal_gen_controller("OFF")
                lockTheONOFFButton(True)
                amplifier_power("OFF")
                extension_power_controller("OFF")


            # Enable the PWM
            write_value(ENABLE_PATH, "1")

            # Wait for a few seconds before reading the temperature again
            time.sleep(5)

    except subprocess.CalledProcessError as e:
        print(f"Command `{e.cmd}` returned with error (code {e.returncode}): {e.output}")

    spi.close()  # Close the SPI device


def download_profile():
    # Download profile and load all profile/global variables
    global MESSAGE_OF_THE_DAY, AUTHENTICATION, SIGLENT, COMMAND, AUTH_KEY, PATH_POST

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
    MESSAGE_OF_THE_DAY = profileData['message_of_the_day']
    print(MESSAGE_OF_THE_DAY)
    print("Auth: " + str(AUTHENTICATION) + " Siglent: " + str(SIGLENT) + " Command: " + str(COMMAND))


def Siglent_SocketConnect():
    global SIGLENT_CONNECTION
    try:
        # create an AF_INET, STREAM socket (TCP)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        # Connect to remote server
        s.connect((SIGLENT_CONNECTION, 5024))
        try:
            Siglent_SocketSend(s, b'*IDN?')
            s.recv(4096)
        except Exception as error:
            return "failed. to connect."
    except socket.error:
        print('failed to connect to ip ' + SIGLENT_CONNECTION)
        SIGLENT_CONNECTION = ""
        return "failed. to connect."
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
        if isinstance(s, str):
            # Socket connection failed
            return 'failed'
        # Socket connection succeeded
        Siglent_SocketSend(s, b'C2:OUTP ON')  # Set CH1 ON
        Siglent_SocketSend(s, b'C1:OUTP ON')  # test
        Siglent_SocketClose(s)  # Close socket
        return 'Query complete.'
    except Exception as error:
        return 'failed'


def OFF():
    try:
        s = Siglent_SocketConnect()
        if isinstance(s, str):
            # Socket connection failed
            return 'failed'
        # Socket connection succeeded
        Siglent_SocketSend(s, b'C2:OUTP OFF')
        Siglent_SocketSend(s, b'C1:OUTP OFF')
        Siglent_SocketClose(s)  # Close socket
        return 'Query complete.'
    except Exception as error:
        return 'failed'


def lockTheONOFFButton(ans):
    global lock
    lock = ans


is_running = False
processing = False
lock = False
start_run_time = None
stop_run_time = None


def signal_gen_controller(mode):
    global SIGLENT, is_running, lock, processing, start_run_time, stop_run_time
    # Control signal generator
    if lock: return
    if not SIGLENT == 1:  # Signal Gen is knockoff
        if not processing:
            if mode == "ON":
                if not is_running:
                    # processing true
                    processing = True
                    #  MHS5200 SIGNAL
                    print("ON")
                    os.system(
                        'sudo ' + HOME_PATH +
                        'MHS-5200-Driver/mhs5200 /dev/ttyUSB0 channel 1 arb 0 amplitude 4 freq 364 on')
                    time.sleep(.4)
                    tube1tube2_controller("ON")
                    start_run_time = time.time()
                    send_statistic('TOTAL_TIMES_USED', "1")
                    is_running = True
                    processing = False
            if mode == "OFF":
                if is_running:
                    processing = True
                    print("OFF")
                    tube1tube2_controller("OFF")
                   # time.sleep(.4)
                    #  MHS5200 SIGNAL
                    os.system(
                        'sudo ' + HOME_PATH +
                        'MHS-5200-Driver/mhs5200 /dev/ttyUSB0 channel 1 arb 0 amplitude 4 freq 364 off')
                    stop_run_time = time.time()
                    run_time = float((stop_run_time - start_run_time) / 60)
                    send_statistic('MINUTES', run_time)
                    is_running = False
                    processing = False
    # Siglent - Expensive
    if not processing:
        if mode == "ON":
            if not is_running:
                processing = True
                # Turn siglent signal
                print("ON")
                result = ON()
                if result == 'Query complete.':
                    print('Signal generator turned on successfully.')
                    tube1tube2_controller("ON")
                    send_statistic('TOTAL_TIMES_USED', "1")
                    start_run_time = time.time()
                    is_running = True
                else:
                    send_statistic('ACTIVE_UPDATE', 'Signal generator failed to turn on:' + result)
                processing = False
        if mode == "OFF":
            if is_running:
                processing = True
                print("OFF")
                tube1tube2_controller("OFF")
                time.sleep(.4)
                result = OFF()
                if result == 'Query complete.':
                    print('Signal generator turned off successfully.')
                    stop_run_time = time.time()
                    run_time = float((stop_run_time - start_run_time) / 60)
                    send_statistic('MINUTES', run_time)
                    is_running = False
                else:
                    tube1tube2_controller("ON")
                    send_statistic('ACTIVE_UPDATE', 'Signal generator failed to turn off:' + result)
                processing = False


def amplifier_power(mode):
    try:
        if mode == "ON":
            # Reversed at relay level terminals
            # Default on at startup
            # GPIO 76 1 AMP ON
            os.system('sudo gpioset 1 84=1')
        elif mode == "OFF":
            # GPIO 76 0 AMP OFF
            os.system('sudo gpioset 1 84=0')
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'power_supply_amp_ Error ' + str(error))


def press_screen_power_button():
    # relay clicked twice to signal
    # power button being pressed
    os.system('sudo gpioset 1 85=1')
    time.sleep(4)
    os.system('sudo gpioset 1 85=0')


def extension_power_controller(mode):
    # Used for siglent
    try:
        if mode == "ON":
            # Reversed at relay level terminals
            # Default on at startup
            # GPIO 80 1 extension_power ON
            os.system('sudo gpioset 1 81=1')
        elif mode == "OFF":
            # GPIO 80 0 extension_power OFF
            os.system('sudo gpioset 1 81=0')
    except Exception as error:
        send_statistic('ACTIVE_UPDATE', 'power_supply_amp_ Error ' + str(error))


def tube1tube2_controller(mode):
    # GPIO output to Tube 1 and 2
    try:
        if mode == "ON":
            # GPIO 79+89 0 TUBE ON
            os.system('sudo gpioset 1 82=0')
            os.system('sudo gpioset 1 83=0')
        elif mode == "OFF":
            # GPIO 79+89 1 TUBE OFF
            os.system('sudo gpioset 1 82=1')
            os.system('sudo gpioset 1 83=1')
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
            COMMAND = 0
        except subprocess.CalledProcessError as err:
            COMMAND = 0
            send_statistic('ACTIVE_UPDATE', str(err))


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


user_timezone = ""


def get_time_zone():
    global user_timezone
    try:
        # send request to ipapi to get timezone based on public IP address
        response = requests.get('https://ipapi.co/timezone/')
        user_timezone = response.text.strip()  # remove whitespace characters from response
        cmd = "sudo timedatectl set-timezone " + str(user_timezone)
        response2 = subprocess.check_output(str(cmd), shell=True)
        send_statistic('ACTIVE_UPDATE', "COMMAND RESPONSE: " + response2.decode("utf-8"))
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


def plug_Wifi(data):
    global WIFI_DRIVER_NAME
    ssid = data['wifi_ssid']
    password = data['wifi_pass']
    print(ssid)
    print(password)
    try:
        with open('/etc/netplan/50-cloud-init.yaml', 'w') as file:
            content = \
                '''network:
                    ethernets:
                        eth0:
                            dhcp4: true
                            dhcp4-overrides:
                                route-metric: 200
                            optional: true
                    version: 2
                    wifis:
                        ''' + WIFI_DRIVER_NAME + ''':
                            optional: true
                            access-points:
                                "''' + ssid + '''":
                                    password: "''' + password + '''"
                            dhcp4: true
                            dhcp4-overrides:
                                route-metric: 100'''
            file.write(content)
        print("Write successful. Rebooting now.")
        os.system('sudo reboot')  # eh, that means need to reload index
        # restart_15()
    except Exception as error:
        print(error)


schedulerThread = None
authenticationThread = None
temperatureThread = None
state_timer_disabled_alarm = "False"
alarmModeSleep = 30  # seconds


def run_pending_jobs():
    while True:
        schedule.run_pending()
        time.sleep(1)


def clearAlarms():
    global alarm_job, timer_job, state_alarm, state_timer
    if alarm_job in schedule.jobs:
        lockTheONOFFButton(False)
        signal_gen_controller("OFF")
        amplifier_power("ON")
        extension_power_controller("ON")
        state_alarm = "Disabled"
        print("Alarm : " + state_alarm)
        schedule.cancel_job(alarm_job)
        press_screen_power_button()
    if timer_job in schedule.jobs:
        signal_gen_controller("OFF")
        state_timer = "Disabled"
        print("Timer : " + state_timer)
        schedule.cancel_job(timer_job)


def timer_action():
    global state_timer, timer_job
    print("Timer : " + state_timer)
    schedule.cancel_job(timer_job)
    state_timer = "Disabled"
    time.sleep(0.5)
    signal_gen_controller("OFF")
    print("Timer Complete")


def alarm_action():
    global state_alarm, alarm_job, timer_job, state_timer, alarmModeSleep
    # turn back on
    lockTheONOFFButton(False)
    signal_gen_controller("OFF")
    amplifier_power("ON")
    extension_power_controller("ON")
    state_alarm = "Disabled"
    print("Alarm : " + state_alarm)
    schedule.cancel_job(alarm_job)
    print("sleeping")
    time.sleep(alarmModeSleep)
    print("done sleeping")
    # do alarm stuff
    print("hello alarm went off")
    timer_job = schedule.every(int(USER_TIMER)).minutes.do(timer_action)
    signal_gen_controller("ON")
    state_timer = "Enabled"
    print("alarm done")
    # turn on display
    press_screen_power_button()
    # should turn back off or do another alarm?
    # I'd like it to do another alarm so I can have it turn on mid night and
    # no spoiling


def start_threads():
    global schedulerThread, authenticationThread, temperatureThread
    # start the scheduler in a separate thread
    if schedulerThread is None or schedulerThread.is_alive() is False:
        schedulerThread = threading.Thread(target=run_pending_jobs)
        schedulerThread.start()
    # start the authentication check thread
    if authenticationThread is None or authenticationThread.is_alive() is False:
        authenticationThread = threading.Thread(target=authentication_check_thread)
        authenticationThread.start()
    # start the temperature check thread
    if temperatureThread is None or not temperatureThread.is_alive():
        temperatureThread = threading.Thread(target=start_Temperature)
        temperatureThread.start()


def kick_it_into_gear():
    download_profile()
    start_threads()
    run_command()
    amplifier_power("ON")
    get_time_zone()
    send_statistic('IP', str(get_my_public_ip()))
    os.system("sudo systemctl restart screensaver")


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
    global temp
    # print(threading.active_count())
    if request.method == 'GET':
        if not ONCE_INDEX: return index()
        return render_template("settings.html", temp=temp)
    if request.method == 'POST':
        data = request.form
        if 'email' in data:
            try:
                send_statistic('ACTIVE_UPDATE', data['email'])
            except Exception as error:
                send_statistic('ACTIVE_UPDATE', 'settings_send failed: email ' + 'email'
                               + str(data['email']) + str(error))
        return load_index()


@app.route('/no_wifi', methods=['GET', 'POST'])
def no_wifi():
    if request.method == 'GET':
        return render_template('setup_wifi.html')
    if request.method == 'POST':
        if not request.is_json:
            plug_Wifi(request.form)
            return "rebooting"
        data = request.json
        if data['button'] == 'back_button':
            if not ONCE_INDEX:
                return "bad"
            return "good"


@app.route('/timer_settings', methods=['GET', 'POST'])
def timer_settings():
    global Profile_filePath, USER_TIMER
    if request.method == 'GET':
        if not ONCE_INDEX: return index()
        # Clear all Timers
        clearAlarms()
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
    global ONCE_INDEX, USER_ALARM
    if request.method == 'GET':
        if not ONCE_INDEX: return index()
        # Clear all Timers
        clearAlarms()
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


timer_job = None
alarm_job = None
state_timer = "Disabled"
state_alarm = "Disabled"


@app.route('/get_state')
def get_state():
    global state_alarm, state_timer
    return jsonify({'state_timer': state_timer, 'state_alarm': state_alarm})


@app.route('/set_state', methods=["POST"])
def set_state():
    global state_alarm, state_timer, alarm_job, timer_job, alarmModeSleep
    data = request.get_json()

    if "Alarm" in data:
        if data.get('Alarm') == "Alarm_on":
            signal_gen_controller("OFF")
            lockTheONOFFButton(True)
            amplifier_power("OFF")
            extension_power_controller("OFF")
            state_alarm = "Enabled"
            print("Alarm : " + state_alarm)
            alarm_job = schedule.every().day.at(USER_ALARM).do(alarm_action)
            send_statistic('ALARMS_USED', '1')
            # Turn display off
            press_screen_power_button()
        if data.get('Alarm') == "Alarm_off":
            lockTheONOFFButton(False)
            signal_gen_controller("OFF")
            amplifier_power("ON")
            extension_power_controller("ON")
            state_alarm = "Disabled"
            print("Alarm : " + state_alarm)
            schedule.cancel_job(alarm_job)
            print("sleeping")
            time.sleep(alarmModeSleep)
            print("done sleeping")
            # Turn display on
            press_screen_power_button()

    if "Timer" in data:
        if data.get('Timer') == "Timer_on":
            print("here")
            timer_job = schedule.every(int(USER_TIMER)).minutes.do(timer_action)
            signal_gen_controller("ON")
            state_timer = "Enabled"
            send_statistic('TIMERS_USED', '1')
            print("Timer : " + state_timer)
        if data.get('Timer') == "Timer_off":
            state_timer = "Disabled"
            print("Timer : " + state_timer)
            schedule.cancel_job(timer_job)
            time.sleep(0.5)
            signal_gen_controller("OFF")

    return jsonify({'state': 'ok'})


@app.route('/load_index', methods=['GET'])
def load_index():
    return render_template('Dashboard.html', message_of_the_day=MESSAGE_OF_THE_DAY)


@app.route('/not_authenticated', methods=['GET'])
def not_authenticated():
    # Turn itself off? On Relay. but how would it turn on. a low voltage?
    return render_template('not_auth.html')


@app.route('/turnon')
def turnon():
    print("ON")
    signal_gen_controller("ON")
    return "Complete"


@app.route('/turnoff')
def turnoff():
    print("OFF")
    signal_gen_controller("OFF")
    return "Complete"
