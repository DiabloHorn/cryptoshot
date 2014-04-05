#!/usr/bin/env python
from flask import Flask
from flask import request

import os
import datetime

"""
    DiabloHorn http://diablohorn.wordpress.com
    Save any uploaded data to a file as binary
"""

app = Flask(__name__)
 
@app.route('/', methods=['POST'])
def root():
    save_dir = request.remote_addr    
    current_timestamp = datetime.datetime.now().strftime("%d%m%y_%H%M%S.%f")    
    if request.method == 'POST':
        if not os.path.exists(save_dir):
            os.makedirs(save_dir)
        #daymonthyear_hourminutesecond.microsecond
        postedfile = open(save_dir + "/" + current_timestamp,'wb')
        postedfile.write(request.data)
        postedfile.close()
    return ""

     
if __name__ == '__main__':
    #remove debug=True if deployed
    app.run(host='0.0.0.0', port=8008, debug=True)
