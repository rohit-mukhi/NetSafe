To start with root privileges:

    sudo .venv/bin/python -m streamlit run main.py

To check isolation:

    ping 8.8.8.8 -c 3

To start the DDOS attack:

    sudo hping3 -S -i u1000 -p 80 127.0.0.1
