from datetime import datetime
import matplotlib.pylab as plot
import pandas as pd

import matplotlib
matplotlib.style.use('ggplot')

# Read data from http bro logs
with open("/Users/tharageshtharun/Downloads/http.log",'r') as infile:
    file_data = infile.read()
    
# Split file by newlines
file_data = file_data.split('\n')

# Remove comment lines
http_data = []
for line in file_data:
    if line[0] is not None and line[0] != "#":
        http_data.append(line)

# Lets analyze user agents
user_agent_analysis = {}
user_agent_overall = {}
for line in http_data:
    # Extract the timestamp
    timestamp = datetime.fromtimestamp(float(line.split('\t')[0]))
    # Strip second and microsecond from timestamp
    timestamp = str(timestamp.replace(second=0,microsecond=0))
    
    # Extract the user agent
    user_agent = line.split('\t')[11]
    
    # Update status code analysis variable
    if user_agent not in user_agent_analysis.keys():
        user_agent_analysis[user_agent] = {timestamp: 1}
    else:
        if timestamp not in user_agent_analysis[user_agent].keys():
            user_agent_analysis[user_agent][timestamp] = 1
        else:
            user_agent_analysis[user_agent][timestamp] += 1
            
    # Update overall user agent count
    if user_agent not in user_agent_overall.keys():
        user_agent_overall[user_agent] = 1
    else:
        user_agent_overall[user_agent] += 1

df = pd.DataFrame.from_dict(user_agent_analysis,orient='columns').fillna(0)
df

df.plot(figsize=(12,9))

ax = df.plot(rot=90,figsize=(12,9))

user_agent_analysis2 = user_agent_analysis
print(user_agent_analysis2.keys())
high_volume_user_agents = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.64 Safari/537.36"
]
for ua in high_volume_user_agents:    
    if ua in user_agent_analysis2.keys():
        del user_agent_analysis2[ua]
df2 = pd.DataFrame.from_dict(user_agent_analysis2,orient='columns').fillna(0)
df2

df2.plot(rot=90,figsize=(12,9))

# Lets analyze status codes
status_code_analysis = {}
status_code_overall = {}
earliest_time = None
latest_time = None
for line in http_data:
    # Extract the timestamp
    timestamp = datetime.fromtimestamp(float(line.split('\t')[0]))
    # Strip minute, second and microsecond from timestamp
    #timestamp = str(timestamp.replace(minute=0,second=0,microsecond=0))
    timestamp = str(timestamp.replace(second=0,microsecond=0))
    
    # Extract the status code
    status_code = line.split('\t')[14]
    
    # Update status code analysis variable
    if status_code not in status_code_analysis.keys():
        status_code_analysis[status_code] = {timestamp: 1}
    else:
        if timestamp not in status_code_analysis[status_code].keys():
            status_code_analysis[status_code][timestamp] = 1
        else:
            status_code_analysis[status_code][timestamp] += 1
            
    # Update overall status code count
    if status_code not in status_code_overall.keys():
        status_code_overall[status_code] = 1
    else:
        status_code_overall[status_code] += 1
    
    # Update our earliest and latest time as needed
    if earliest_time is None or timestamp < earliest_time:
        earliest_time = timestamp
    if latest_time is None or timestamp > latest_time:
        latest_time = timestamp

# Format data for the plot function
status_label = []
data = []
for code in sorted(status_code_overall.keys()):
    status_label.append(str(code) + " (" + str(status_code_overall[code]) + ")")
    data.append(status_code_overall[code])

plot.figure(1,figsize=[8,8])
patches, texts = plot.pie(data, shadow=True, startangle=90)
plot.legend(patches, status_label,loc="best")
plot.title('Status Code Distribution')
plot.axis('equal')
plot.tight_layout()
plot.show()

# Output the status codes in table form
df = pd.DataFrame.from_dict(status_code_analysis,orient='columns').fillna(0)
df

# Plot the status codes
df.plot(rot=90,figsize=(12,9))

# Remove the 200 status code and re-plot the status codes
status_code_analysis2 = status_code_analysis
if '200' in status_code_analysis2.keys():
    del status_code_analysis2['200']
print(status_code_analysis2.keys())
df2 = pd.DataFrame.from_dict(status_code_analysis2,orient='columns').fillna(0)
df2.plot(rot=90, figsize=(12,9))
