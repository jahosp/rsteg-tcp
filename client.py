#!/usr/bin/python3
# -*- coding: UTF-8 -*-
# Author: jahos@protonmail.com

import PySimpleGUIQt as sg
import logging
from utils import is_ipv4


logger = logging.getLogger(__name__)

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
                [sg.Text('Secret data', size=(8, 1)), sg.Input(key='http_secret'), sg.FileBrowse()]
            ], visible=False, key='post_details')]

        ], visible=False, key='http_frame')]

    # TCP Frame Layout
    tcp_frame = [
        sg.Frame('TCP Parameters', layout=[
            [sg.Text('Destination Host IP', size=(15, 1)), sg.InputText(enable_events=True, key='dhost')],
            [sg.Text('Destination Port ', size=(15, 1)), sg.InputText(enable_events=True, key='dport',
                                                                      default_text='80')],
            [sg.Text('Cover data', size=(8, 1)), sg.Input(key='cover'), sg.FileBrowse()],
            [sg.Text('Secret data', size=(8, 1)), sg.Input(key='secret'), sg.FileBrowse()],
            [sg.Text('Send as:'), sg.Combo(values=['HTTP', 'TCP Only'], default_value='HTTP', readonly=True,
                                           auto_size_text=True)],
            [sg.Text('Retransmission probability'),
             sg.InputText(default_text='0.07', enable_events=True, key='prob')],
        ], visible=False, key='tcp_frame')]

    # Application General Layout
    layout = [[sg.Text('First select which protocol do you want to use: ')],
              [
                  sg.Checkbox('HTTP', key='http', enable_events=True),
                  sg.Checkbox('Raw TCP', key='tcp', enable_events=True)
              ],
              tcp_frame,
              http_frame,
              [sg.HorizontalSeparator("grey")],
              [sg.Text('STATUS')],
              [sg.Output(size=(40, 10), key='-OUTPUT-')],
              [sg.HorizontalSeparator()],
              [sg.Button('Submit'), sg.Button('Clear log')]]

    # Create the window
    window = sg.Window('RSTEG TCP', layout)
    # Render flags
    http_visible_flag = False
    tcp_visible_flag = False
    post_details_flag = False

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
            window.refresh()

        # Submit form event
        if event == 'Submit' and values['dhost'] and values['dport'] and values['sport'] \
                and values['cover'] and values['secret']:
            # Let's validate the form input
            if is_ipv4(values['dhost']):
                if 1 <= int(values['dport']) <= 65535:
                    if 1 <= int(values['sport']) <= 65535:
                        print('Parameters are valid!')
                        print('Starting RSTEG TCP')
                        window.refresh()

                    else:
                        print('Source Port is not valid.')
                else:
                    print('Destination Port is not valid.')
            else:
                print('Destination Host IP is not valid.')

        # Clear log event
        if event == 'Clear log':
            window['-OUTPUT-'].update('')

    # Remove window from screen
    window.close()