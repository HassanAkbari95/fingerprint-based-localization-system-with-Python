
########################################## LIBRARIES ###############################################################
# Libraries

import turtle
from turtle import *
from scapy.all import *
from threading import Thread
import pandas as pd
import time
import os
import csv
import sklearn
from scapy.layers.dot11 import Dot11Beacon, Dot11
from sklearn.utils import shuffle
from sklearn.neighbors import KNeighborsClassifier
from sklearn import linear_model
from sklearn import preprocessing
import numpy as np


########################################## GLOBAL VARIABLES ##############################################################
#Empty vector to put the rssi of the selected APs
rssi = [0, 0, 0, 0, 0, 0, 0, 0]

########################################## FUNCTIONS ######################################################################
'''
Funciton 1: Function to set points to each part of location area under studying
Function 2: Function for detecting rssi of selected APs and estimating the position of the current location based on KNN algorithm
Function 3: Function for going through all 2.4 GHz channels

'''	

# Function 1
def positioning(tmp_pos):
    if tmp_pos == 1:                                                    #Reference Point 1: ENTRANCE
        pos.setx(140)
        pos.sety(-100)
    elif tmp_pos == 2:                                                  #Reference Point 2: KITCHEN
        pos.setx(200)
        pos.sety(80)
    elif tmp_pos == 3:                                                  #Reference Point 3: LIVING ROOM
        pos.setx(80)
        pos.sety(90)        
    elif tmp_pos == 4:                                                  #Reference Point 4: ROOM 1  
        pos.setx(-50)
        pos.sety(0)
    elif tmp_pos == 5:                                                  #Reference Point 5: GUEST ROOM  
        pos.setx(-125)
        pos.sety(0)
    elif tmp_pos == 6:                                                  #Reference Point 6: ROOM 2 
        pos.setx(-200)
        pos.sety(-90)
    elif tmp_pos == 7:                                                  #Reference Point 7: ROOM 3   
        pos.setx(-125)
        pos.sety(-160)    
    pos.clear()  


# Function 2 
def fingerprinting(packet):
    if packet.haslayer(Dot11Beacon):        #just considering beacon frames
        bssid = packet[Dot11].addr2         #MAC address of corresponding received packet
        if bssid == "74:da:88:64:14:32":    #Assigning signal strength to selected AP if it is exist
            try:
                signal_strength = packet.dBm_AntSignal       #Signal strength of corresponding received packet
            except:
                signal_strength = "N/A"
            rssi[0] = signal_strength                        #Assigning signal strength to selected AP
        elif bssid == "88:41:fc:1b:e0:ec": 
            try:
                signal_strength = packet.dBm_AntSignal
            except:
                signal_strength = "N/A"
            rssi[1] = signal_strength
        elif bssid == "f8:3d:ff:60:2e:ee": 
            try:
                signal_strength = packet.dBm_AntSignal
            except:
                signal_strength = "N/A"
            rssi[2] = signal_strength
        elif bssid == "60:e3:27:2e:66:7e": 
            try:
                signal_strength = packet.dBm_AntSignal
            except:
                signal_strength = "N/A"
            rssi[3] = signal_strength
        elif bssid == "60:e3:27:34:23:e0":
            try:
                signal_strength = packet.dBm_AntSignal
            except:
                signal_strength = "N/A"
            rssi[4] = signal_strength
        elif bssid == "60:e3:27:2e:66:80": 
            try:
                signal_strength = packet.dBm_AntSignal
            except:
                signal_strength = "N/A"
            rssi[5] = signal_strength  
        elif bssid == "8c:aa:b5:a2:05:c9": 
            try:
                signal_strength = packet.dBm_AntSignal
            except:
                signal_strength = "N/A"
            rssi[6] = signal_strength
        elif bssid == "68:1a:b2:80:43:29":
            try:
                signal_strength = packet.dBm_AntSignal
            except:
                signal_strength = "N/A"
            rssi[7] = signal_strength                                                            
                    
        train_data = pd.read_csv("Database")                            #Loading database 
        df_train = pd.DataFrame(train_data)
        X_train_tmp = df_train.to_numpy()
        X_train_RSSI_vectors = X_train_tmp[:, 1:]
        X_train_Reference_Points = X_train_tmp[:, 0]
        X_test_RSSI_vectors = [rssi]
        model = KNeighborsClassifier(n_neighbors=9)
        model.fit(X_train_RSSI_vectors, X_train_Reference_Points)
        predicted = model.predict(X_test_RSSI_vectors)
        position = int(predicted)                                       #Current position of the user
        os.system("clear")                                              #Cleaning the terminal space to increase clearness
        print(rssi)                                                     #Printing RSSIs received to user in its current position
        print(position)                                                 #Printing current position of the user
        #time.sleep(0.1)                                                 #Sleeping time before going to the next step
        positioning(position)                                           #Showing the position of the user in the provided map


# Function 3	
def change_channel():                                                   #In the place of this report there are 13 channels for 2.4 GHz band, APs can work in different channels
    ch = 1
    while True:
        if ch > 13:
            ch = 1
        else:
            os.system(f"iwconfig {interface} channel {ch}")             #Assigning the channel and its corresond channel to system
            ch = ch + 1
        time.sleep(0.1)
            
#################################################### BODY ##############################################################################            
if __name__ == "__main__":
    interface = "wlp2s0mon"                                         #The name of the wi-fi interface on monitor mode
    channel_changer = Thread(target=change_channel)                 #Running change_channel as a thread function
    channel_changer.daemon = True
    channel_changer.start()
    screen = turtle.Screen()                                        #Creating the Screen Interface
    screen.setup(width=700, height=700, startx=400, starty=50)      #Adjusting the Screen limitations
    screen.title('MY HOUSE')                                        #The title of the Screen
    screen.bgpic('room.gif')                                        #Import the background of the screen. The 'room.gif' file must be in the same directory with this code.
    pos = turtle.Turtle()                                           #Creating the turtle object as "pos". This will helps us to use "pos" instead of using "turtle" all the time.
    pos.speed(1)  # The speed of drawing the line                   #It is used to adjust the rate of change of position of the arrow that occurs during position change.
    pos.pensize(5)  # The width of the line                         #It is used to adjust the thickness of the road that occurs during the position change.
    pos.clear()                                                     #It is used to clear the previous road.
    sniff(iface=interface, prn=fingerprinting)                      #Start sniffing on defined interface by using defined function in the name of fingerprinting
    

