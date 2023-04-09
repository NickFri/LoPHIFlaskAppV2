from Dashboard import app, os

if __name__ == "__main__":
    # os.system("sudo systemctl restart screensaver")
    app.run(host='127.0.0.1', port=5000, debug=True)
    # app.run(host='0.0.0.0', port=5000, debug=True)
