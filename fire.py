import pandas as pd
from datetime import timedelta
import matplotlib.pyplot as plt
import seaborn as sns

df = pd.read_csv(r'/Users/tharageshtharun/Downloads/sysmon.csv')
df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%m/%d/%Y %H:%M')
df = df.sort_values('Timestamp')

# Parsing
'''
def read_and_preprocess_csv(sysmon_path):
    dataframe = pd.read_csv(sysmon_path)

    # Parse timestamps
    dataframe['Timestamp'] = pd.to_datetime(dataframe['Timestamp'], format="%m/%d/%Y %H:%M")

    # Sort the DataFrame by Timestamp
    dataframe = dataframe.sort_values('Timestamp')
    
    # Converting Event IDs and Process IDs to integers and handling NaN values
    dataframe['EventID'] = pd.to_numeric(dataframe['EventID'], errors='coerce').astype('Int64')
    dataframe['ProcessId'] = pd.to_numeric(dataframe['ProcessId'], errors='coerce').astype('Int64')

    # Handle missing values
    dataframe[['Image', 'CommandLine', 'SourceIp', 'DestinationIp']] = dataframe[['Image', 'CommandLine', 'SourceIp', 'DestinationIp']].replace('', pd.NA)
    return dataframe
'''
E_PROC, E_NET, E_OK, E_FAIL, E_LOGOFF = 1, 3, 4624, 4625, 4634
print(f"Loaded {len(df)} events")
print(f"Date range: {df['Timestamp'].min()} to {df['Timestamp'].max()}")
print(f"Event types: {sorted(df['EventID'].unique())}")
print(f"Users: {sorted(df['User'].unique())}")
print("\nFirst few rows:")
print(df.head())

#------------------------------------------
MIN_FAILED_ATTEMPTS = 4
TIME_WINDOW_HOURS = 200

print(f"--- Multiple Failed Logins Followed by a Successful Login ---")
print(f"(Detecting >= {MIN_FAILED_ATTEMPTS} failures within a {TIME_WINDOW_HOURS}-hour window of a success)")
print("-" * 70)

failed_login_timestamps = {}
found_suspicious_login = False

for index, row in df.iterrows():
    user = row['User']
    event_type = row['EventType']
    timestamp = row['Timestamp']
    
    if user not in failed_login_timestamps:
        failed_login_timestamps[user] = []

    if event_type == 'LoginFailure':
        failed_login_timestamps[user].append(timestamp)

    elif event_type == 'LoginSuccess':
        time_window = timedelta(hours=TIME_WINDOW_HOURS)
        
        recent_failures = [
            t for t in failed_login_timestamps[user] if timestamp - t <= time_window
        ]

        if len(recent_failures) >= MIN_FAILED_ATTEMPTS:
            found_suspicious_login = True
            print(f"Suspicious login for user '{user}': {len(recent_failures)} failed attempts followed by a success.")
            print(f"  Successful login at: {timestamp}")
            print(f"  Preceding failed attempts within the {TIME_WINDOW_HOURS}-hour window:")
            for failure_time in recent_failures:
                print(f"    - {failure_time}")
            print("\n")
        
        failed_login_timestamps[user] = []

if not found_suspicious_login:
    print("No instances found matching the specified criteria.")
    print("Consider adjusting MIN_FAILED_ATTEMPTS or TIME_WINDOW_HOURS if you expect to see results.")

#------------------------------------------
print("\n\n--- Suspicious Process Launches (powershell with encoded commands or mimikatz.exe) ---")
suspicious_processes = df[
    (df['Image'].str.contains('mimikatz.exe', case=False, na=False)) |
    (df['CommandLine'].str.contains('powershell.exe -enc', case=False, na=False)) |
    (df['CommandLine'].str.contains('mimikatz.exe', case=False, na=False)) |
    (df['CommandLine'].str.contains('Invoke-WebRequest http://malicious.com', na=False))
]

if not suspicious_processes.empty:
    for index, row in suspicious_processes.iterrows():
        print(f"Timestamp: {row['Timestamp']}, User: {row['User']}, Image: {row['Image']}, CommandLine: {row['CommandLine']}")
else:
    print("No suspicious process launches found.")
print("-" * 70)

#------------------------------------------
print("\n\n--- Multiple Network Connections to the Same IP by a User ---")
network_connections = df[df['EventType'] == 'NetworkConnect']
connection_counts = network_connections.groupby(['User', 'DestinationIp']).size().reset_index(name='Count')

suspicious_connections = connection_counts[connection_counts['Count'] > 1]

if not suspicious_connections.empty:
    for index, row in suspicious_connections.iterrows():
        print(f"User '{row['User']}' connected to IP '{row['DestinationIp']}' {row['Count']} times.")
else:
    print("No users found making multiple connections to the same IP.")
print("-" * 70)

#------------------------------------------
print("\n\n--- Short Login-Logout Sessions (< 10 minutes) ---")
user_sessions = {}
for index, row in df.iterrows():
    user = row['User']
    event_type = row['EventType']
    timestamp = row['Timestamp']

    if user not in user_sessions:
        user_sessions[user] = {'login_time': None}

    if event_type == 'LoginSuccess':
        user_sessions[user]['login_time'] = timestamp
    elif event_type == 'Logout':
        if user_sessions[user]['login_time']:
            session_duration = timestamp - user_sessions[user]['login_time']
            if session_duration.total_seconds() / 60 < 10:
                print(f"User '{user}' had a short session of {session_duration}")
        user_sessions[user]['login_time'] = None
print("-" * 70)

# HEATMAP - User activity by hour
print("Creating heatmap...")
heatmap_data = df.pivot_table(index='User', columns=df['Timestamp'].dt.hour, values='EventID', aggfunc='count', fill_value=0)

# Plot heatmap
plt.figure(figsize=(12, 6))
sns.heatmap(heatmap_data, cmap='Reds', annot=True, fmt='d')
plt.title('User Activity Heatmap by Hour')
plt.xlabel('Hour of Day')
plt.ylabel('User')
plt.show()

# BOX PLOT - Time intervals between events
print("Creating box plot...")
plt.figure(figsize=(10, 6))
interval_data = []
event_labels = []

for event_id in sorted(df['EventID'].unique()):
    event_times = df[df['EventID'] == event_id]['Timestamp'].sort_values()
    if len(event_times) > 1:
        intervals = event_times.diff().dt.total_seconds() / 60  # Convert to minutes
        intervals = intervals.dropna()
        if len(intervals) > 0:
            interval_data.append(intervals)
            event_labels.append(f'Event {event_id}')

if interval_data:
    plt.boxplot(interval_data, tick_labels=event_labels)
    plt.title('Time Intervals Between Events')
    plt.xlabel('Event Type')
    plt.ylabel('Interval (Minutes)')
    # plt.yscale('log')
    # plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# SPARKLINES - All users activity over time in single graph
print("Creating sparklines...")
plt.figure(figsize=(14, 8))

users = df['User'].unique()
colors = ['blue', 'red', 'green', 'orange', 'purple', 'brown', 'pink', 'gray', 'olive', 'cyan']

for i, user in enumerate(users):
    user_data = df[df['User'] == user].set_index('Timestamp')
    hourly_counts = user_data.resample('h').size()

    color = colors[i % len(colors)]  # Cycle through colors if more users than colors
    plt.plot(hourly_counts.index, hourly_counts.values,
             color=color, linewidth=2, label=f'{user}', marker='o', markersize=3)

plt.title('User Activity Sparklines - All Users Comparison', fontsize=16)
plt.xlabel('Time')
plt.ylabel('Events per Hour')
plt.legend(bbox_to_anchor=(1, 1), loc='upper left')
plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

#user level - event id
df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")

unique_eventids = sorted(df["EventID"].unique())
eventid_map = {eid: idx for idx, eid in enumerate(unique_eventids)}
df["EventID_mapped"] = df["EventID"].map(eventid_map)

users = df["User"].unique()
for user in users:
    user_df = df[df["User"] == user]
    plt.figure(figsize=(10, 2))  # sparkline style
    plt.plot(user_df["Timestamp"], user_df["EventID_mapped"])
    # plt.yticks(range(len(unique_eventids)), unique_eventids, fontsize=6)  # show actual EventIDs on y-axis
    plt.title(f"User: {user}", fontsize=8, loc="left")
    plt.tight_layout()
    plt.show()
    
# Also create a summary of total activity per user //optional - to see last - for spark lines
print("\nUser Activity Summary:")
user_activity = df['User'].value_counts().sort_values(ascending=False)
for user, count in user_activity.items():
    print(f"  {user}: {count} total events")
print(f"\nMost active user: {user_activity.index[0]} ({user_activity.iloc[0]} events)")
print(f"Least active user: {user_activity.index[-1]} ({user_activity.iloc[-1]} events)")

# Bar graph
user_event_counts = df.groupby('User')['EventID'].count().sort_values()
user_event_counts.plot(kind='bar', figsize=(12, 6))
plt.title('Event Counts per User')
plt.xlabel('User')
plt.ylabel('Count')
plt.show()
df.groupby('EventType').size().plot(kind='barh')
df.groupby('Image').size().plot(kind='barh')
plt.show()
