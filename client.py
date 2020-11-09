#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com
import time
from urllib.parse import urlparse
from http_client import HttpClient
from rsteg_socket import RstegSocket
import matplotlib.pyplot as plt
import numpy as np
import os
import subprocess
#import PySimpleGUIQt as sg
import PySimpleGUIQt as sg
import logging
import re
from utils import is_ipv4
logger = logging.getLogger(__name__)

# Regex for validating URL
regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

def get(host, path):
    print('Sending GET ' + path + ' HTTP/1.1 request to ' + host)
    window.refresh()
    c = HttpClient(49512)
    req = c.create_get_request(host, path)
    logger.debug('GET request created.')
    logger.debug(req)
    res = c.request(bytes(req), host)
    print('Response: ' + res.split(b'\r\n')[0].decode())
    window.refresh()

    return res

def show_html(res):
    try:
        payload = res.split(b'\r\n\r\n')[1].decode()
        f = open('res.html', 'w')
        f.write(payload)
        f.close()
    except Exception as e:
        print('Error: ' + str(e))
    subprocess.Popen(['su', 'jahos', '-c', 'firefox file://' + os.path.realpath('res.html')])

def post(host, path, data):
    cover = open(data, 'rb').read()
    print('Sending POST ' + path + ' HTTP/1.1 request to ' + host)
    window.refresh()
    print('RSTEG not activated.')
    window.refresh()
    c = HttpClient(49512)
    req = c.create_post_request(host, path, cover, 'image/jpg')
    res = c.request(bytes(req), host)
    print('Response: ' + res.split(b'\r\n')[0].decode())
    window.refresh()

    return res

def rpost(host, path, data, secret_data, rprob):
    cover = open(data, 'rb').read()
    secret = open(secret_data, 'rb').read()
    print('Sending POST ' + path + ' HTTP/1.1 request to ' + host)
    print('Using RSTEG to send secret.')
    window.refresh()
    c = HttpClient(49512, rprob)
    req = c.create_post_request(host, path, cover, 'image/jpg')
    res = c.rsteg_request(bytes(req), secret, host)
    print('Response: ' + res.split(b'\r\n')[0].decode())

    return res

def tcp_transfer(host, sport, dport, data, secret_data, rprob):


    cover = open(data, 'rb').read()
    secret = open(secret_data, 'rb').read()
    print('Opening TCP stream at ' + host + ':' + dport)
    window.refresh()
    s = RstegSocket(int(sport), float(rprob))
    s.connect(host, int(dport))
    print('Connection established.')
    window.refresh()
    start_time = time.time()
    sec = s.rsend(cover, secret)
    end_time = time.time() - start_time
    print('Data sent, closing connection.')
    window.refresh()
    s.close()
    window.refresh()
    plot_time(end_time, len(cover), sec)

def plot_time(time, bytes, secret_bytes):
    try:
        bytes_array = np.arange(start=0, stop=bytes, step=(bytes/5))
        time_array = np.arange(start=0, stop=time, step=(time/5))
        secret_array = np.arange(start=0, stop=secret_bytes, step=(secret_bytes/5))
        plt.plot(time_array, bytes_array, color='red', label='cover')
        plt.plot(time_array, secret_array, color='blue', label='secret', linestyle='--')
        plt.ylabel('Data transferred (bytes)')
        plt.xlabel('Time (s)')
        plt.legend(loc='lower right')
        plt.show(block=False)
    except Exception as e:
        print('Error: ' + str(e))
        window.refresh()


# Start point
if __name__ == '__main__':
    # Logger configuration
    logging.basicConfig(filename='client.log',
                        filemode='w',
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %I:%M:%S %p',
                        level=logging.DEBUG)
    logger.setLevel(logging.DEBUG)

    # Application Layout
    sg.theme('Default')

    # HTTP Frame Layout
    http_frame = [
        sg.Frame('HTTP Parameters', layout=[
            [sg.Text('URL :', size=(15,1)), sg.InputText(enable_events=True, key='url')],
            [sg.Text('Request type: ', size=(15,1)), sg.Combo(values=['GET', 'POST'], default_value='GET', readonly=True,
                                                              auto_size_text=True, enable_events=True, key='http_request')],
            [sg.Frame('Data', layout=[
                [sg.Text('Cover data', size=(8, 1)), sg.Input(key='http_cover'), sg.FileBrowse()],
                [sg.Text('Secret data', size=(8, 1)), sg.Input(key='http_secret'), sg.FileBrowse()],
                [
                    sg.Checkbox('RSTEG', key='rsteg', enable_events=True),
                    sg.Text('Retransmission probability'), sg.InputText(default_text='0.07', enable_events=True, key='rprob')
                ]
            ], visible=False, key='post_details')]
        ], visible=False, key='http_frame')]

    # TCP Frame Layout
    tcp_frame = [
        sg.Frame('TCP Parameters', layout=[
            [sg.Text('Destination Host IP', size=(15, 1)), sg.InputText(enable_events=True, key='dhost')],
            [sg.Text('Destination Port ', size=(15, 1)), sg.InputText(enable_events=True, key='dport',
                                                                      default_text='80')],
            [sg.Text('Source Port ', size=(15, 1)), sg.InputText(enable_events=True, key='sport',
                                                                      default_text='49512')],
            [sg.Text('Cover data', size=(8, 1)), sg.Input(key='cover'), sg.FileBrowse()],
            [sg.Text('Secret data', size=(8, 1)), sg.Input(key='secret'), sg.FileBrowse()],
            [sg.Text('Retransmission probability'),
             sg.InputText(default_text='0.07', enable_events=True, key='prob')],
        ], visible=False, key='tcp_frame')]

    upper_menu_layout = [['Help', 'About'],]


    # Application General Layout
    layout = [ [sg.Menu(upper_menu_layout)],

              [sg.Text('First select which protocol do you want to use: ')],
              [
                  sg.Checkbox('HTTP', key='http', enable_events=True),
                  sg.Checkbox('Raw TCP', key='tcp', enable_events=True)
              ],
              tcp_frame,
              http_frame,
              [sg.Frame('STATUS LOG', layout=[
                  [sg.Output(size=(40, 15), key='-OUTPUT-')],
              ])],
              [sg.Button('Submit'), sg.Button('Clear log')]]

    upper_menu_layout = [
        ['Help'],
        ['About']
    ]


    # Create the window
    window = sg.Window('RSTEG TCP', layout, location=(1920/3,1080/3), auto_size_text=14)
    # Render flags
    http_visible_flag = False
    tcp_visible_flag = False
    post_details_flag = False
    c = HttpClient(49512)
    # Window Event Loop
    while True:
        event, values = window.read()
        # Quit event
        if event == sg.WINDOW_CLOSED:
            break
        # Render HTTP frame event
        if event == 'http':
            http_visible_flag = not http_visible_flag
            window['http_frame'].update(visible=http_visible_flag)
            window['tcp_frame'].update(visible=False)
            window.refresh()
        # Render POST details frame event
        if event == 'http_request':
            if values['http_request'] == 'POST':
                post_details_flag = not post_details_flag
                window['post_details'].update(visible=post_details_flag)
                window.refresh()
            if values['http_request'] == 'GET':
                post_details_flag = False
                window['post_details'].update(visible=post_details_flag)
                window.refresh()
        # Render TCP frame event
        if event == 'tcp':
            tcp_visible_flag = not tcp_visible_flag
            window['tcp_frame'].update(visible=tcp_visible_flag)
            window['http_frame'].update(visible=False)
            window.refresh()

        # Submit form event
        if event == 'Submit':
            # HTTP Submit
            if values['http']:
                if values['url'] and values['http_request']:
                    url = values['url']
                    req_type = values['http_request']
                    if re.match(regex, url) is not None:
                        o = urlparse(url)
                        path = o.path
                        host = (o.netloc).split(':')[0]
                        if req_type == 'GET':  # Do HTTP GET
                            res = get(host, path)
                            show_html(res)
                            # sg.popup_scrolled(res.decode(), title='Response', size=(30, 20))
                            window.refresh()
                        else:  # Do HTTP POST
                            if values['http_cover']:
                                if values['rsteg'] and values['rprob'] and values['http_secret']:
                                    res = rpost(host, path, values['http_cover'], values['http_secret'], values['rprob'])
                                else:
                                    res = post(host, path, values['http_cover'])
                                sg.popup_scrolled(res.decode(), title='Response', size=(30, 20))
                                window.refresh()
                            else:
                                print('No data selected!')
                    else:
                        print('Bad URL!')
                else:
                    print('Must fill all the parameters!')

            # TCP Submit
            if values['tcp']:
                if values['dhost'] and values['dport'] and values['sport'] and values['cover'] and values['secret']:
                    # Let's validate the form input
                    if is_ipv4(values['dhost']):
                        if 1 <= int(values['dport']) <= 65535:
                            if 1 <= int(values['sport']) <= 65535:
                                print('Parameters are valid!')
                                print('Starting RSTEG TCP')
                                window.refresh()
                                tcp_transfer(values['dhost'], values['sport'], values['dport'],
                                             values['cover'], values['secret'], values['prob'])
                                window.refresh()
                            else:
                                print('Source Port is not valid.')
                        else:
                            print('Destination Port is not valid.')
                    else:
                        print('Destination Host IP is not valid.')

        if event == 'About':
            screen_dim= window.GetScreenDimensions()
            sg.popup('Version 1.0', 'www.github.com/jahosp/rsteg-tcp', title='About', location=(screen_dim[0]/2-30,screen_dim[1]/2-30))
        # Clear log event
        if event == 'Clear log':
            window['-OUTPUT-'].update('')


    # Remove window from screen
    window.close()