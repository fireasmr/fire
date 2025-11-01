# ------------------------------------------------------------------------------
import pandas as pd

df = pd.read_csv("/content/server_logs.csv")

freq_table = pd.crosstab(
    index=df['user_id'],
    columns=df['status'],
    normalize='index'
) * 100

desired_columns = ['success','failed']

freq_table = freq_table.reindex(columns=desired_columns, fill_value=0)

freq_table = freq_table.sort_index()

print("User Event Type Distribution (%):")
print(freq_table.round(2))

# ------------------------------------------------------------------------------

network data baselining

📊 Step 2: Frequency Table Analysis

This part corresponds to “what talks to what, how often, and how much”
(from the Splunk and Colasoft baselining guides).

a) Basic frequency table
index=main
| stats count sum(Flows) as total_flows sum(Bytes) as total_bytes by src_ip dest_ip Protocol dest_port
| sort - total_flows


Shows top communication pairs by total flow and byte volume.

🟢 Insight: Top pairs = most frequent connections (baseline “who talks to whom”).

b) Protocol frequency
index=main
| stats count sum(Flows) as total_flows sum(Bytes) as total_bytes by Protocol
| sort - total_flows


This gives a quick baseline of traffic distribution by protocol type (TCP, UDP, ICMP, etc.).

c) Destination port frequency
index=main
| stats count sum(Flows) as total_flows sum(Bytes) as total_bytes by dest_port
| sort - total_flows


Helps identify which ports dominate traffic (e.g., 443, 80, 22).

🧠 Step 3: Build a Statistical Baseline (without MLTK)

We’ll calculate average, standard deviation, and thresholds manually.

a) Average and deviation of flows per source IP
index=main
| stats avg(Flows) as avg_flows stdev(Flows) as stdev_flows by src_ip
| eval upper_threshold = avg_flows + (2 * stdev_flows)
| table src_ip avg_flows stdev_flows upper_threshold


This gives the expected normal range of flows for each source.

b) Detect deviations from baseline
index=main
| eventstats avg(Flows) as avg_flows stdev(Flows) as stdev_flows by src_ip
| eval upper_threshold = avg_flows + (2 * stdev_flows)
| eval anomaly = if(Flows > upper_threshold, "YES", "NO")
| table _time src_ip dest_ip Flows avg_flows stdev_flows upper_threshold anomaly


🔍 Interpretation:

If anomaly=YES, that src_ip generated abnormally high flow count compared to its baseline average.

c) Baseline for bytes transferred
index=main
| eventstats avg(Bytes) as avg_bytes stdev(Bytes) as stdev_bytes by src_ip
| eval upper_threshold = avg_bytes + (3 * stdev_bytes)
| eval anomaly = if(Bytes > upper_threshold, "YES", "NO")
| table _time src_ip dest_ip Bytes avg_bytes stdev_bytes upper_threshold anomaly

🕒 Step 4: Time-based Baselining

The Splunk blogs used timechart for behaviour over a window (hour/day).
We can replicate that easily:

index=main
| bin _time span=1m
| stats sum(Flows) as total_flows sum(Bytes) as total_bytes by _time src_ip
| eventstats avg(total_flows) as avg_flows stdev(total_flows) as stdev_flows by src_ip
| eval threshold = avg_flows + (2 * stdev_flows)
| eval is_anomaly = if(total_flows > threshold, "YES", "NO")
| timechart span=1m sum(total_flows) as flows by src_ip


🕵️‍♂️ Use this to visualize deviations in a timechart.

🔍 Step 5: Identify “central” or “important” nodes (without GraphCentrality)

We can approximate node centrality using basic metrics:

index=main
| stats dc(dest_ip) as distinct_dests sum(Flows) as total_flows sum(Bytes) as total_bytes by src_ip
| eval centrality_score = (distinct_dests * total_flows)
| sort - centrality_score


Top entries ≈ “most central” nodes — those talking to many others with high volume.



# ------------------------------------------------------------------------------
# 1. STATISTICAL BASELINING (Mean ± 3σ)
# ------------------------------------------------------------------------------
index=my_index earliest=-30d@d latest=now
| eventstats avg(my_numeric_field) as global_avg, stdev(my_numeric_field) as global_std
`comment(&quot;Compute global mean and stdev across all events&quot;)`
| eval z_score = abs(my_numeric_field - global_avg) / (global_std + 0.0001) `comment(&quot;Z-score;
small epsilon avoids divide-by-zero&quot;)`
| where z_score &gt; 3 `comment(&quot;Flag values &gt;3 standard deviations from mean&quot;)`
| table _time, my_field, my_numeric_field, global_avg, global_std, z_score
`comment(&quot;Why: Robust parametric method; assumes normality or large sample; detects
extreme outliers&quot;)`


# ------------------------------------------------------------------------------
# 2. PROBABILITY-BASED BASELINING (Rarity via Frequency)
# ------------------------------------------------------------------------------
index=my_index earliest=-30d@d latest=now
| stats count by my_field `comment(&quot;Count occurrences of each categorical value&quot;)`
| eventstats sum(count) as total_events `comment(&quot;Total events for probability denominator&quot;)`
| eval probability = round(count * 100.0 / total_events, 4) `comment(&quot;Probability as percentage&quot;)`
| sort +count
| eval rarity_rank = if(probability &lt; 0.1, &quot;RARE&quot;, if(probability &lt; 1, &quot;UNCOMMON&quot;, &quot;COMMON&quot;))
`comment(&quot;Tiered rarity classification&quot;)`
| table my_field, count, probability, rarity_rank
`comment(&quot;Why: Non-parametric; defines normal by empirical frequency; ideal for categorical
fields like users, IPs, commands&quot;)`


# ------------------------------------------------------------------------------
# 3. REGRESSION-BASED BASELINING (Time-Series Forecasting)
# ------------------------------------------------------------------------------

modified:
  source="network_traffic.csv" host="LAPTOP-AB9KUD9J" sourcetype="csv"
  | eval my_numeric_field = 'packet_size'
  | predict my_numeric_field ⁠ comment("Local Linear Prediction with 95% confidence bands") ⁠
  |eval upper95='upper95(prediction(my_numeric_field))', lower95='lower95(prediction(my_numeric_field))'
  | eval anomaly = case(
      my_numeric_field > upper95, "HIGH",
      my_numeric_field < lower95, "LOW",
      1=1, "NORMAL"
    ) 
  | table _time, my_numeric_field, prediction(my_numeric_field), lower95(prediction(my_numeric_field)), upper95(prediction(my_numeric_field)), deviation, anomaly
  | timechart  sum(my_numeric_field), sum(prediction(my_numeric_field))

# -----------------REAL ------------------------------------------------------------
index=my_index earliest=-30d@d latest=now
| timechart span=1h count as my_numeric_field `comment(&quot;Aggregate metric over time (use any
numeric: bytes, duration, etc.)&quot;)`

| predict my_numeric_field algorithm=LLP future_timespan=24 `comment(&quot;Local Linear
Prediction with 95% confidence bands&quot;)`
| eval deviation = abs(my_numeric_field - prediction)
| eval anomaly = case(
my_numeric_field &gt; upper95, &quot;HIGH&quot;,
my_numeric_field &lt; lower95, &quot;LOW&quot;,
1=1, &quot;NORMAL&quot;
) `comment(&quot;Compare actual vs. forecast bounds&quot;)`
| table _time, my_numeric_field, prediction, lower95, upper95, deviation, anomaly
`comment(&quot;Why: Captures trends, seasonality, and expected variance; detects contextual
anomalies in time-series data&quot;)`


# ------------------------------------------------------------------------------
From Splunk - CIDDS Docs
Statistics based
| tstats sum(Flows) as sum_flows WHERE (index=cidds &quot;Src IP
Addr&quot;=192.168.220.15) BY _time span=5m
| eval HourOfDay=strftime(_time, &quot;%H&quot;), DayOfWeek=strftime(_time, &quot;%A&quot;)
| eval Weekday=if(DayOfWeek=&quot;Saturday&quot; OR DayOfWeek=&quot;Sunday&quot;,&quot;No&quot;,&quot;Yes&quot;)
| eventstats avg(&quot;sum_flows&quot;) as avg_f stdev(&quot;sum_flows&quot;) as stdev by
&quot;HourOfDay&quot;, &quot;Weekday&quot;
| eval lower_bound=(avg_f-stdev*exact(3)), upper_bound=(avg_f+stdev*exact(3))
| eval isOutlier=if(&#39;avg&#39; &lt; lowerBound OR &#39;avg&#39; &gt; upperBound, 1, 0)
| table _time sum_flows lower_bound upper_bound

Prob den based
| tstats sum(Flows) as sum_flows WHERE (index=cidds &quot;Src IP
Addr&quot;=192.168.220.15) BY _time span=5m
| eval HourOfDay=strftime(_time, &quot;%H&quot;), DayOfWeek=strftime(_time, &quot;%A&quot;)
| eval Weekday=if(DayOfWeek=&quot;Saturday&quot; OR DayOfWeek=&quot;Sunday&quot;,&quot;No&quot;,&quot;Yes&quot;)
| fit DensityFunction sum_flows by &quot;Weekday,HourOfDay&quot; as outlier into
df_192_168_220_15 threshold=0.003

Regression based:
| tstats sum(Flows) as sum_flows avg(Bytes) as avg_bytes sum(Bytes) as
sum_bytes avg(Duration) as avg_duration sum(Packets) as sum_packets dc(&quot;Dst
IP Addr&quot;) as distinct_connections WHERE (index=cidds &quot;Src IP
Addr&quot;=192.168.220.15) BY _time span=5m
| eval HourOfDay=strftime(_time, &quot;%H&quot;), DayOfWeek=strftime(_time, &quot;%A&quot;)
| eval Weekday=if(DayOfWeek=&quot;Saturday&quot; OR DayOfWeek=&quot;Sunday&quot;,0,1)
| fit SystemIdentification sum_flows from avg_bytes sum_bytes avg_duration
sum_packets distinct_connections HourOfDay Weekday dynamics=3-3-3-3-3-3-3-3
conf_interval=99 into si_dur_cidds

# ------------------------------------------------------------------------------
stats
Ouery: index=my_index | stats count by my_field
● Explanation: Performs statistical aggregations like count, sum, avg, grouped by fields.
  
eval
Ouery: index=my_index | eval status=if(my_field=“error“,1,0)
● Explanation: Creates or modifies fields using expressions and functions.

timechart
Ouery: index=my_index | timechart span=1h count
● Explanation: Plots aggregated data over time with automatic time binning.

Ouery: index=my_index | top my_{ield
● Explanation: Returns the most frequent values of a field with count and percent.

rare
Ouery: index=my_index | rare my_field
● Explanation: Returns the least frequent values of a field with count and percent.

dedup
Query: index=my_index dedup my_field
● Explanation: Removes duplicate events based on one or more fields.

Ouery: index=my_index | sort -count
● Explanation: Orders results by specified fields, ascending (+) or descending (-). 
                                                                                
head
● Query: :tndex=my_:Index | head 10
● Explanation: Returns the first N results of the current sorted dataset.

tail
Ouery: index=my_index | tail 10
● Explanation: Returns the last N results of the current sorted dataset.

where
Query: index=my_index where my_numezic_Iield &gt; 1000
● Explanation: Filters events based on a boolean expression.

table
Ouery: index=my_index | table my_field, _time, count
● Explanation: Displays only the specified fields in tabular format.

fields
Ouery: index=my_index | fields my_iield, my_numeric_field
● Explanation: Keeps or removes specified fields from results.

rename
Ouery: index=my_index | rename src_ip as source_ip
● Explanation: Renames one or more fields for clarity.
                                         
search
Ouery: index=my_index my_field=“value“
● Explanation: Filters events at search time using key-value or boolean logic

eventstats
Query: index=my_index eventstats avg(my_numezic_field) as avg_va1
● Explanation: Generates aggregate stats across all events, keeps original events.
  
streamstats
Query: index=my_index streamstats count as seq by my_field
● Explanation: Computes running or windowed stats as events stream in.

transaction
● Query: :tndex=my_1ndex | transact::fon my_I:held maxspan=5m
● Explanation: Groups related events into transactions based on fields and time.

chart
● Query: :tndex=my_1ndex | chart count ovez my_I:held by stat:us
● Explanation: Creates a table with one dimension on rows, another on columns.

append
Ouery: index=my_index1 | append [search index=my_index2]
● Explanation: Appends results of a subsearch to the current results.

join
Ouery: index=my_index | join my_field [search index=lookup_index]
● Explanation: Joins results with a subsearch on a common field (use with caution).


--------------------------SMR network baseline-----------------------------


import csv
import pandas as pd
from collections import Counter
import statistics

def create_network_baseline(filename, baseline_output="network_baseline.csv"):


    print("="*80)
    print("NETWORK BASELINING ANALYSIS")
    print("="*80)
    print(f"\nAnalyzing network traffic from: {filename}\n")

    # Read network traffic data
    df = pd.read_csv(filename)
    total_records = len(df)

    print(f"Total network packets/connections analyzed: {total_records}\n")

    baseline_metrics = []

    # 1. PROTOCOL DISTRIBUTION
    print("📊 Analyzing Protocol Distribution...")
    protocol_counts = df['protocol'].value_counts()
    for protocol, count in protocol_counts.items():
        percentage = (count / total_records) * 100
        baseline_metrics.append({
            'Metric_Category': 'Protocol_Distribution',
            'Metric_Name': protocol,
            'Count': count,
            'Percentage': round(percentage, 2),
            'Average_Value': '-',
            'Min_Value': '-',
            'Max_Value': '-',
            'Std_Deviation': '-'
        })

    # 2. BANDWIDTH ANALYSIS
    print("📈 Analyzing Bandwidth Usage...")
    total_bytes = df['bytes_transferred'].sum()
    avg_bytes = df['bytes_transferred'].mean()
    min_bytes = df['bytes_transferred'].min()
    max_bytes = df['bytes_transferred'].max()
    std_bytes = df['bytes_transferred'].std()

    baseline_metrics.append({
        'Metric_Category': 'Bandwidth',
        'Metric_Name': 'Total_Bytes_Transferred',
        'Count': total_records,
        'Percentage': 100.0,
        'Average_Value': round(avg_bytes, 2),
        'Min_Value': min_bytes,
        'Max_Value': max_bytes,
        'Std_Deviation': round(std_bytes, 2)
    })


    for protocol in df['protocol'].unique():
        protocol_data = df[df['protocol'] == protocol]
        protocol_bytes = protocol_data['bytes_transferred'].sum()
        protocol_percentage = (protocol_bytes / total_bytes) * 100

        baseline_metrics.append({
            'Metric_Category': 'Bandwidth_By_Protocol',
            'Metric_Name': f'{protocol}_Bandwidth',
            'Count': len(protocol_data),
            'Percentage': round(protocol_percentage, 2),
            'Average_Value': round(protocol_data['bytes_transferred'].mean(), 2),
            'Min_Value': protocol_data['bytes_transferred'].min(),
            'Max_Value': protocol_data['bytes_transferred'].max(),
            'Std_Deviation': round(protocol_data['bytes_transferred'].std(), 2)
        })

    # 3. LATENCY ANALYSIS
    print("⏱️  Analyzing Network Latency...")
    avg_latency = df['latency_ms'].mean()
    min_latency = df['latency_ms'].min()
    max_latency = df['latency_ms'].max()
    std_latency = df['latency_ms'].std()

    baseline_metrics.append({
        'Metric_Category': 'Latency',
        'Metric_Name': 'Network_Latency_ms',
        'Count': total_records,
        'Percentage': '-',
        'Average_Value': round(avg_latency, 2),
        'Min_Value': min_latency,
        'Max_Value': max_latency,
        'Std_Deviation': round(std_latency, 2)
    })

    # 4. PACKET SIZE ANALYSIS
    print("📦 Analyzing Packet Sizes...")
    avg_packet = df['packet_size'].mean()
    min_packet = df['packet_size'].min()
    max_packet = df['packet_size'].max()
    std_packet = df['packet_size'].std()

    baseline_metrics.append({
        'Metric_Category': 'Packet_Size',
        'Metric_Name': 'Packet_Size_Bytes',
        'Count': total_records,
        'Percentage': '-',
        'Average_Value': round(avg_packet, 2),
        'Min_Value': min_packet,
        'Max_Value': max_packet,
        'Std_Deviation': round(std_packet, 2)
    })

    # 5. PORT USAGE ANALYSIS
    print("🔌 Analyzing Port Usage...")
    dest_port_counts = df['destination_port'].value_counts()
    for port, count in dest_port_counts.items():
        percentage = (count / total_records) * 100
        baseline_metrics.append({
            'Metric_Category': 'Destination_Port_Usage',
            'Metric_Name': f'Port_{port}',
            'Count': count,
            'Percentage': round(percentage, 2),
            'Average_Value': '-',
            'Min_Value': '-',
            'Max_Value': '-',
            'Std_Deviation': '-'
        })

    # 6. TOP TALKERS (Source IPs)
    print("💬 Analyzing Top Talkers (Source IPs)...")
    source_ip_counts = df['source_ip'].value_counts()
    for ip, count in source_ip_counts.items():
        percentage = (count / total_records) * 100
        ip_traffic = df[df['source_ip'] == ip]['bytes_transferred'].sum()

        baseline_metrics.append({
            'Metric_Category': 'Source_IP_Traffic',
            'Metric_Name': ip,
            'Count': count,
            'Percentage': round(percentage, 2),
            'Average_Value': round(ip_traffic / count, 2),
            'Min_Value': '-',
            'Max_Value': '-',
            'Std_Deviation': '-'
        })

    # 7. CONNECTION STATE ANALYSIS
    print("🔗 Analyzing Connection States...")
    state_counts = df['connection_state'].value_counts()
    for state, count in state_counts.items():
        percentage = (count / total_records) * 100
        baseline_metrics.append({
            'Metric_Category': 'Connection_State',
            'Metric_Name': state,
            'Count': count,
            'Percentage': round(percentage, 2),
            'Average_Value': '-',
            'Min_Value': '-',
            'Max_Value': '-',
            'Std_Deviation': '-'
        })

    # Create baseline DataFrame and save
    baseline_df = pd.DataFrame(baseline_metrics)
    baseline_df.to_csv(baseline_output, index=False)

    print(f"\n{'='*80}")
    print(f"✅ Network baseline created successfully!")
    print(f"📁 Saved to: {baseline_output}")
    print(f"{'='*80}\n")

    # Display summary
    print("NETWORK BASELINE SUMMARY:")
    print("-"*80)
    print(baseline_df.to_string(index=False))

    return baseline_df

def detect_network_anomalies(new_traffic_file, baseline_file="network_baseline.csv",
                            output_file="network_anomalies.csv",
                            deviation_threshold=30, latency_threshold=100):


    print("\n" + "="*80)
    print("NETWORK ANOMALY DETECTION")
    print("="*80)
    print(f"\nAnalyzing new traffic from: {new_traffic_file}\n")

    # Read baseline and new traffic
    baseline_df = pd.read_csv(baseline_file)
    new_df = pd.read_csv(new_traffic_file)

    total_new = len(new_df)
    print(f"New packets/connections to analyze: {total_new}\n")

    anomalies = []

    # 1. Check Protocol Distribution Anomalies
    print("🔍 Checking for protocol anomalies...")
    protocol_baseline = baseline_df[baseline_df['Metric_Category'] == 'Protocol_Distribution']

    for protocol in new_df['protocol'].unique():
        current_count = len(new_df[new_df['protocol'] == protocol])
        current_percentage = (current_count / total_new) * 100

        baseline_row = protocol_baseline[protocol_baseline['Metric_Name'] == protocol]

        if baseline_row.empty:
            anomalies.append({
                'Anomaly_Type': 'New Protocol',
                'Metric': 'Protocol',
                'Value': protocol,
                'Current_Percentage': round(current_percentage, 2),
                'Baseline_Percentage': 0,
                'Deviation': round(current_percentage, 2),
                'Severity': 'High'
            })
        else:
            baseline_percentage = baseline_row.iloc[0]['Percentage']
            deviation = abs(current_percentage - baseline_percentage)

            if deviation > deviation_threshold:
                anomalies.append({
                    'Anomaly_Type': 'Protocol Deviation',
                    'Metric': 'Protocol',
                    'Value': protocol,
                    'Current_Percentage': round(current_percentage, 2),
                    'Baseline_Percentage': baseline_percentage,
                    'Deviation': round(deviation, 2),
                    'Severity': 'High' if deviation > 50 else 'Medium'
                })

    # 2. Check Latency Anomalies
    print("🔍 Checking for latency anomalies...")
    avg_latency = new_df['latency_ms'].mean()
    latency_baseline = baseline_df[baseline_df['Metric_Name'] == 'Network_Latency_ms']

    if not latency_baseline.empty:
        baseline_latency = latency_baseline.iloc[0]['Average_Value']
        latency_deviation = abs(avg_latency - baseline_latency)
        latency_deviation_pct = (latency_deviation / baseline_latency) * 100

        if latency_deviation_pct > deviation_threshold or avg_latency > latency_threshold:
            anomalies.append({
                'Anomaly_Type': 'High Latency',
                'Metric': 'Latency_ms',
                'Value': round(avg_latency, 2),
                'Current_Percentage': '-',
                'Baseline_Percentage': baseline_latency,
                'Deviation': round(latency_deviation, 2),
                'Severity': 'High' if avg_latency > latency_threshold else 'Medium'
            })

    # 3. Check Bandwidth Anomalies
    print("🔍 Checking for bandwidth anomalies...")
    total_bytes = new_df['bytes_transferred'].sum()
    avg_bytes = new_df['bytes_transferred'].mean()

    bandwidth_baseline = baseline_df[baseline_df['Metric_Name'] == 'Total_Bytes_Transferred']
    if not bandwidth_baseline.empty:
        baseline_avg_bytes = bandwidth_baseline.iloc[0]['Average_Value']
        bytes_deviation = abs(avg_bytes - baseline_avg_bytes)
        bytes_deviation_pct = (bytes_deviation / baseline_avg_bytes) * 100

        if bytes_deviation_pct > deviation_threshold:
            anomalies.append({
                'Anomaly_Type': 'Bandwidth Deviation',
                'Metric': 'Average_Bytes',
                'Value': round(avg_bytes, 2),
                'Current_Percentage': '-',
                'Baseline_Percentage': baseline_avg_bytes,
                'Deviation': round(bytes_deviation_pct, 2),
                'Severity': 'High' if bytes_deviation_pct > 50 else 'Medium'
            })

    # 4. Check for Unusual Port Activity
    print("🔍 Checking for unusual port activity...")
    port_baseline = baseline_df[baseline_df['Metric_Category'] == 'Destination_Port_Usage']

    for port in new_df['destination_port'].unique():
        port_count = len(new_df[new_df['destination_port'] == port])
        port_percentage = (port_count / total_new) * 100

        baseline_port = port_baseline[port_baseline['Metric_Name'] == f'Port_{port}']

        if baseline_port.empty and port_percentage > 5:
            anomalies.append({
                'Anomaly_Type': 'New Port Activity',
                'Metric': 'Destination_Port',
                'Value': port,
                'Current_Percentage': round(port_percentage, 2),
                'Baseline_Percentage': 0,
                'Deviation': round(port_percentage, 2),
                'Severity': 'Medium'
            })

    # Save and display results
    if anomalies:
        anomaly_df = pd.DataFrame(anomalies)
        anomaly_df = anomaly_df.sort_values('Severity', ascending=False)
        anomaly_df.to_csv(output_file, index=False)

        print(f"\n⚠️  {len(anomalies)} NETWORK ANOMALIES DETECTED!")
        print(f"📁 Anomaly report saved to: {output_file}\n")
        print("NETWORK ANOMALY REPORT:")
        print("-"*80)
        print(anomaly_df.to_string(index=False))
    else:
        print("\n✅ No network anomalies detected - traffic is within normal baseline!")

    return anomalies

def main():

    print("\n" + "="*80)
    print("STEP 1: CREATING NETWORK BASELINE")
    print("="*80 + "\n")

    traffic_file = "network_traffic.csv"
    create_network_baseline(traffic_file, "network_baseline.csv")


    print("\n" + "="*80)
    print("✅ NETWORK BASELINING COMPLETE!")
    print("="*80)

if __name__ == "__main__":
    main()

--------------------------SMR normal baseline-----------------------------

import csv
import pandas as pd
from collections import Counter
from datetime import datetime

def create_baseline(filename, baseline_output="baseline.csv"):


    print(f"Creating baseline from: {filename}")
    print("="*70)

    # Read the log file
    with open(filename, 'r') as file:
        reader = csv.DictReader(file)
        data = list(reader)

    if not data:
        print("No data found!")
        return

    total_records = len(data)
    print(f"Total records: {total_records}\n")


    columns = data[0].keys()

    baseline_data = []


    for column in columns:
        if column == 'timestamp':
            continue

        print(f"Analyzing: {column}")


        values = [row[column] for row in data]
        frequency = Counter(values)


        for value, count in frequency.items():
            percentage = (count / total_records) * 100

            baseline_data.append({
                'Column': column,
                'Value': value,
                'Baseline_Count': count,
                'Baseline_Percentage': round(percentage, 2),
                'Total_Records': total_records,
                'Status': 'Normal' if percentage >= 5 else 'Rare'
            })


    df = pd.DataFrame(baseline_data)
    df = df.sort_values(['Column', 'Baseline_Count'], ascending=[True, False])


    df.to_csv(baseline_output, index=False)

    print(f"\n{'='*70}")
    print(f"✓ Baseline created and saved to: {baseline_output}")
    print(f"{'='*70}\n")


    print("BASELINE SUMMARY:")
    print("-"*70)
    print(df.to_string(index=False))

    return df

def detect_anomalies(new_logfile, baseline_file="baseline.csv",
                     output_file="anomaly_report.csv", threshold=20):


    print(f"\nDetecting anomalies in: {new_logfile}")
    print("="*70)


    baseline_df = pd.read_csv(baseline_file)


    with open(new_logfile, 'r') as file:
        reader = csv.DictReader(file)
        new_data = list(reader)

    if not new_data:
        print("No new data found!")
        return

    total_new_records = len(new_data)
    print(f"New records to analyze: {total_new_records}\n")

    anomalies = []
    columns = new_data[0].keys()


    for column in columns:
        if column == 'timestamp':
            continue


        values = [row[column] for row in new_data]
        current_freq = Counter(values)

        for value, count in current_freq.items():
            current_percentage = (count / total_new_records) * 100


            baseline_row = baseline_df[
                (baseline_df['Column'] == column) &
                (baseline_df['Value'] == value)
            ]

            if baseline_row.empty:

                anomalies.append({
                    'Column': column,
                    'Value': value,
                    'Current_Count': count,
                    'Current_Percentage': round(current_percentage, 2),
                    'Baseline_Percentage': 0,
                    'Deviation': round(current_percentage, 2),
                    'Anomaly_Type': 'New Value',
                    'Severity': 'High' if current_percentage > 10 else 'Medium'
                })
            else:
                baseline_percentage = baseline_row.iloc[0]['Baseline_Percentage']
                deviation = abs(current_percentage - baseline_percentage)

                if deviation > threshold:
                    anomalies.append({
                        'Column': column,
                        'Value': value,
                        'Current_Count': count,
                        'Current_Percentage': round(current_percentage, 2),
                        'Baseline_Percentage': baseline_percentage,
                        'Deviation': round(deviation, 2),
                        'Anomaly_Type': 'Frequency Deviation',
                        'Severity': 'High' if deviation > 50 else 'Medium'
                    })


    if anomalies:
        anomaly_df = pd.DataFrame(anomalies)
        anomaly_df = anomaly_df.sort_values('Deviation', ascending=False)
        anomaly_df.to_csv(output_file, index=False)

        print(f"⚠ {len(anomalies)} ANOMALIES DETECTED!")
        print(f"Anomaly report saved to: {output_file}\n")
        print("ANOMALY REPORT:")
        print("-"*70)
        print(anomaly_df.to_string(index=False))
    else:
        print("✓ No anomalies detected - behavior matches baseline!")

    return anomalies

def main():

    print("\n" + "="*70)
    print("STEP 1: CREATING BASELINE")
    print("="*70 + "\n")

    baseline_logfile = "server_logs.csv"
    create_baseline(baseline_logfile, "baseline.csv")

    print("\n" + "="*70)
    print("BASELINE ANALYSIS COMPLETE!")
    print("="*70)

if __name__ == "__main__":
    main()


# --------------------------- yyyyyy --------------------------------

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

df = pd.read_csv("network_metrics.csv", parse_dates=['timestamp'])
df = df.sort_values('timestamp').reset_index(drop=True)

df_agg = df.set_index('timestamp').resample('5T').agg({
    'flows': 'sum',
    'bytes': 'sum',
    'duration': 'mean',
    'packets': 'sum',
    'distinct_hosts': 'nunique'
}).reset_index()

df_agg = df_agg.fillna(method='ffill').fillna(0)


df_agg['hour'] = df_agg['timestamp'].dt.hour
df_agg['dayofweek'] = df_agg['timestamp'].dt.dayofweek
df_agg['is_weekend'] = df_agg['dayofweek'].isin([5, 6]).astype(int)
df_agg['is_business_hours'] = df_agg['hour'].between(9, 17).astype(int)

df_agg['hour_sin'] = np.sin(2 * np.pi * df_agg['hour'] / 24)
df_agg['hour_cos'] = np.cos(2 * np.pi * df_agg['hour'] / 24)

for lag in [1, 2, 3, 6, 12]:
    df_agg[f'flows_lag{lag}'] = df_agg['flows'].shift(lag)
    df_agg[f'bytes_lag{lag}'] = df_agg['bytes'].shift(lag)

windows = [6, 12, 24]
for window in windows:
    df_agg[f'flows_rolling_mean_{window}'] = df_agg['flows'].rolling(window=window, min_periods=1).mean()
    df_agg[f'flows_rolling_std_{window}'] = df_agg['flows'].rolling(window=window, min_periods=1).std()
    df_agg[f'flows_rolling_max_{window}'] = df_agg['flows'].rolling(window=window, min_periods=1).max()
    df_agg[f'flows_rolling_min_{window}'] = df_agg['flows'].rolling(window=window, min_periods=1).min()

df_agg['flows_diff'] = df_agg['flows'].diff()
df_agg['flows_pct_change'] = df_agg['flows'].pct_change().fillna(0)

df_agg['bytes_per_flow'] = df_agg['bytes'] / (df_agg['flows'] + 1)
df_agg['packets_per_flow'] = df_agg['packets'] / (df_agg['flows'] + 1)

df_agg = df_agg.iloc[24:].reset_index(drop=True)
grouped = df_agg.groupby(['hour', 'is_weekend'])
df_agg['mean_flows'] = grouped['flows'].transform('mean')
df_agg['std_flows'] = grouped['flows'].transform('std')
df_agg['median_flows'] = grouped['flows'].transform('median')

df_agg['mad_flows'] = grouped['flows'].transform(lambda x: np.median(np.abs(x - np.median(x))))

df_agg['upper_3std'] = df_agg['mean_flows'] + 3 * df_agg['std_flows']
df_agg['lower_3std'] = df_agg['mean_flows'] - 3 * df_agg['std_flows']
df_agg['upper_mad'] = df_agg['median_flows'] + 3 * 1.4826 * df_agg['mad_flows']
df_agg['lower_mad'] = df_agg['median_flows'] - 3 * 1.4826 * df_agg['mad_flows']

df_agg['is_outlier_stat'] = (
    (df_agg['flows'] > df_agg['upper_3std']) |
    (df_agg['flows'] < df_agg['lower_3std'])
).astype(int)

print("\n" + "="*70)
print("BASELINE THRESHOLDS - What Separates Normal from Abnormal")
print("="*70)

print("\n1. OVERALL BASELINE (All Data):")
print(f"   Mean flows: {df_agg['flows'].mean():.2f}")
print(f"   Median flows: {df_agg['flows'].median():.2f}")
print(f"   Std deviation: {df_agg['flows'].std():.2f}")
print(f"   Global upper threshold (mean + 3σ): {df_agg['flows'].mean() + 3*df_agg['flows'].std():.2f}")
print(f"   Global lower threshold (mean - 3σ): {max(0, df_agg['flows'].mean() - 3*df_agg['flows'].std()):.2f}")

print("\n2. TIME-BASED BASELINES (Hour + Weekend/Weekday):")
baseline_summary = df_agg.groupby(['hour', 'is_weekend']).agg({
    'mean_flows': 'first',
    'upper_3std': 'first',
    'lower_3std': 'first',
    'median_flows': 'first',
    'upper_mad': 'first',
    'lower_mad': 'first'
}).round(2)

print("\n   Peak Business Hours (9 AM - 5 PM, Weekday):")
peak_hours = baseline_summary.loc[[(h, 0) for h in range(9, 18) if (h, 0) in baseline_summary.index]]
if len(peak_hours) > 0:
    print(f"   Average baseline: {peak_hours['mean_flows'].mean():.2f} flows")
    print(f"   Upper threshold: {peak_hours['upper_3std'].mean():.2f} flows")
    print(f"   Lower threshold: {peak_hours['lower_3std'].mean():.2f} flows")

print("\n   Off-Peak Hours (6 PM - 8 AM, Weekday):")
off_peak = baseline_summary.loc[[(h, 0) for h in list(range(18, 24)) + list(range(0, 9)) if (h, 0) in baseline_summary.index]]
if len(off_peak) > 0:
    print(f"   Average baseline: {off_peak['mean_flows'].mean():.2f} flows")
    print(f"   Upper threshold: {off_peak['upper_3std'].mean():.2f} flows")
    print(f"   Lower threshold: {off_peak['lower_3std'].mean():.2f} flows")

print("\n   Weekend Activity:")
weekend = baseline_summary.loc[[(h, 1) for h in range(24) if (h, 1) in baseline_summary.index]]
if len(weekend) > 0:
    print(f"   Average baseline: {weekend['mean_flows'].mean():.2f} flows")
    print(f"   Upper threshold: {weekend['upper_3std'].mean():.2f} flows")
    print(f"   Lower threshold: {weekend['lower_3std'].mean():.2f} flows")

print("\n3. DETAILED BASELINE TABLE (Sample - Every 3 Hours):")
print(f"{'Hour':<6} {'Day Type':<12} {'Baseline':<12} {'Upper Limit':<15} {'Lower Limit':<15}")
print("-" * 70)
for hour in range(0, 24, 3):
    for is_wknd in [0, 1]:
        day_type = "Weekend" if is_wknd == 1 else "Weekday"
        if (hour, is_wknd) in baseline_summary.index:
            row = baseline_summary.loc[(hour, is_wknd)]
            print(f"{hour:02d}:00  {day_type:<12} {row['mean_flows']:>10.2f}  {row['upper_3std']:>13.2f}  {row['lower_3std']:>13.2f}")
print("-" * 70)

feature_cols = [
    'hour', 'is_weekend', 'is_business_hours', 'hour_sin', 'hour_cos',
    'flows_lag1', 'flows_lag2', 'flows_lag3', 'flows_lag6', 'flows_lag12',
    'bytes_lag1', 'bytes_lag2', 'bytes_lag3',
    'flows_rolling_mean_6', 'flows_rolling_std_6',
    'flows_rolling_mean_12', 'flows_rolling_std_12',
    'flows_diff', 'flows_pct_change',
    'bytes_per_flow', 'packets_per_flow'
]

X = df_agg[feature_cols].fillna(0)
y = df_agg['flows']

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

rf_model = RandomForestRegressor(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_scaled, y)

df_agg['flows_pred'] = rf_model.predict(X_scaled)
df_agg['residual'] = df_agg['flows'] - df_agg['flows_pred']
df_agg['residual_abs'] = np.abs(df_agg['residual'])

rmse = np.sqrt(mean_squared_error(y, df_agg['flows_pred']))
mae = mean_absolute_error(y, df_agg['flows_pred'])
print(f"Model Performance:")
print(f"  RMSE: {rmse:.2f}")
print(f"  MAE: {mae:.2f}")
print(f"  R²: {rf_model.score(X_scaled, y):.4f}")

threshold_model = np.percentile(df_agg['residual_abs'], 99)
df_agg['is_outlier_model'] = (df_agg['residual_abs'] > threshold_model).astype(int)

print("\n4. MACHINE LEARNING MODEL THRESHOLD:")
print(f"   Residual threshold (99th percentile): ±{threshold_model:.2f}")
print(f"   → Any prediction error > {threshold_model:.2f} is flagged as anomaly")
print(f"   → This means actual flows differ from predicted by more than {threshold_model:.2f}")

iso_features = feature_cols + ['flows', 'bytes', 'packets']
X_iso = df_agg[iso_features].fillna(0)
X_iso_scaled = scaler.fit_transform(X_iso)

iso = IsolationForest(
    contamination=0.02,
    random_state=42,
    n_estimators=100
)
df_agg['anomaly_iforest'] = iso.fit_predict(X_iso_scaled)
df_agg['is_outlier_iforest'] = (df_agg['anomaly_iforest'] == -1).astype(int)
df_agg['anomaly_score'] = iso.score_samples(X_iso_scaled)

iso_threshold = df_agg[df_agg['is_outlier_iforest']==1]['anomaly_score'].max() if df_agg['is_outlier_iforest'].sum() > 0 else None
print("\n5. ISOLATION FOREST ANOMALY THRESHOLD:")
print(f"   Contamination rate: 2% (expecting 2% of data to be anomalies)")
if iso_threshold:
    print(f"   Anomaly score threshold: {iso_threshold:.4f}")
    print(f"   → Scores below {iso_threshold:.4f} are flagged as anomalies")
    print(f"   → Lower scores = more anomalous")
else:
    print("   No anomalies detected by Isolation Forest")

print("\n" + "="*70)
print()

df_agg['anomaly_vote'] = (
    df_agg['is_outlier_stat'] +
    df_agg['is_outlier_model'] +
    df_agg['is_outlier_iforest']
)

df_agg['severity'] = 'Normal'
df_agg.loc[df_agg['anomaly_vote'] == 1, 'severity'] = 'Low'
df_agg.loc[df_agg['anomaly_vote'] == 2, 'severity'] = 'Medium'
df_agg.loc[df_agg['anomaly_vote'] == 3, 'severity'] = 'High'

feature_importance = pd.DataFrame({
    'feature': feature_cols,
    'importance': rf_model.feature_importances_
}).sort_values('importance', ascending=False)

print("\nTop 10 Most Important Features:")
print(feature_importance.head(10).to_string(index=False))

print("\n" + "="*60)
print("ANOMALY DETECTION SUMMARY")
print("="*60)
print(f"Total data points: {len(df_agg)}")
print(f"Statistical outliers: {df_agg['is_outlier_stat'].sum()} ({df_agg['is_outlier_stat'].mean()*100:.2f}%)")
print(f"Model outliers: {df_agg['is_outlier_model'].sum()} ({df_agg['is_outlier_model'].mean()*100:.2f}%)")
print(f"IsolationForest outliers: {df_agg['is_outlier_iforest'].sum()} ({df_agg['is_outlier_iforest'].mean()*100:.2f}%)")
print(f"\nSeverity Distribution:")
print(df_agg['severity'].value_counts())

fig = plt.figure(figsize=(18, 12))

ax1 = plt.subplot(3, 2, 1)
plt.plot(df_agg['timestamp'], df_agg['flows'], label='Actual', alpha=0.7, linewidth=1)
plt.plot(df_agg['timestamp'], df_agg['flows_pred'], label='Predicted', alpha=0.8, linewidth=1.5)
plt.fill_between(df_agg['timestamp'], df_agg['lower_3std'], df_agg['upper_3std'],
                 color='orange', alpha=0.2, label='±3σ bounds')
high_anomalies = df_agg[df_agg['severity'] == 'High']
plt.scatter(high_anomalies['timestamp'], high_anomalies['flows'],
           color='red', s=100, label='High Severity', zorder=5, edgecolors='darkred', linewidths=2)
plt.xlabel('Time')
plt.ylabel('Flows')
plt.title('Network Traffic with Anomaly Detection')
plt.legend()
plt.grid(alpha=0.3)

ax2 = plt.subplot(3, 2, 2)
plt.scatter(df_agg['timestamp'], df_agg['residual'], alpha=0.5, s=10)
plt.axhline(y=threshold_model, color='r', linestyle='--', label='Threshold')
plt.axhline(y=-threshold_model, color='r', linestyle='--')
plt.axhline(y=0, color='black', linestyle='-', alpha=0.3)
plt.xlabel('Time')
plt.ylabel('Residual (Actual - Predicted)')
plt.title('Model Residuals')
plt.legend()
plt.grid(alpha=0.3)

ax3 = plt.subplot(3, 2, 3)
plt.hist(df_agg['anomaly_score'], bins=50, alpha=0.7, edgecolor='black')
plt.xlabel('Anomaly Score (Isolation Forest)')
plt.ylabel('Frequency')
plt.title('Anomaly Score Distribution')
plt.axvline(x=df_agg[df_agg['is_outlier_iforest']==1]['anomaly_score'].max(),
           color='r', linestyle='--', label='Anomaly Threshold')
plt.legend()
plt.grid(alpha=0.3)

ax4 = plt.subplot(3, 2, 4)
hourly_stats = df_agg.groupby('hour').agg({
    'flows': ['mean', 'std'],
    'is_outlier_stat': 'sum'
})
hourly_stats.columns = ['mean', 'std', 'anomalies']
plt.plot(hourly_stats.index, hourly_stats['mean'], marker='o', label='Average Flows')
plt.fill_between(hourly_stats.index,
                 hourly_stats['mean'] - hourly_stats['std'],
                 hourly_stats['mean'] + hourly_stats['std'],
                 alpha=0.3)
ax4_twin = ax4.twinx()
ax4_twin.bar(hourly_stats.index, hourly_stats['anomalies'], alpha=0.3, color='red', label='Anomaly Count')
ax4_twin.set_ylabel('Anomaly Count', color='red')
ax4.set_xlabel('Hour of Day')
ax4.set_ylabel('Flow Count')
ax4.set_title('Hourly Traffic Pattern with Anomalies')
ax4.legend(loc='upper left')
ax4_twin.legend(loc='upper right')
plt.grid(alpha=0.3)

ax5 = plt.subplot(3, 2, 5)
top_features = feature_importance.head(10)
plt.barh(range(len(top_features)), top_features['importance'])
plt.yticks(range(len(top_features)), top_features['feature'])
plt.xlabel('Importance')
plt.title('Top 10 Feature Importances')
plt.grid(alpha=0.3)

ax6 = plt.subplot(3, 2, 6)
heatmap_data = df_agg.pivot_table(
    values='anomaly_vote',
    index='hour',
    columns='dayofweek',
    aggfunc='sum'
)
sns.heatmap(heatmap_data, cmap='YlOrRd', annot=True, fmt='.0f', cbar_kws={'label': 'Anomaly Count'})
plt.xlabel('Day of Week (0=Mon, 6=Sun)')
plt.ylabel('Hour of Day')
plt.title('Anomaly Heatmap by Time')

plt.tight_layout()
plt.savefig('network_anomaly_analysis.png', dpi=300, bbox_inches='tight')
plt.show()

anomalies_df = df_agg[df_agg['anomaly_vote'] >= 2][
    ['timestamp', 'flows', 'flows_pred', 'residual', 'severity', 'anomaly_vote']
].sort_values('timestamp')

anomalies_df.to_csv('detected_anomalies.csv', index=False)
print(f"\n✓ Detected {len(anomalies_df)} significant anomalies")
print(f"✓ Results saved to 'detected_anomalies.csv'")
print(f"✓ Visualization saved to 'network_anomaly_analysis.png'")

if len(anomalies_df) > 0:
    print("\nSample Detected Anomalies:")
    print(anomalies_df.head(10).to_string(index=False))

# -------------------------------------- coburg ---------------------------------------------------

import csv
import pandas as pd
from collections import Counter
from datetime import datetime
import numpy as np

def create_baseline(filename, baseline_output="cidds_baseline.csv", normal_filter=True):
    print(f"Creating baseline from: {filename}")
    print("="*70)
    column_names = ['Date first seen', 'duration', 'Proto', 'Src IP Addr', 'Src Pt', 'Dst IP Addr', 'Dst Pt', 'Packets', 'Bytes', 'Flows', 'Flags', 'Tos', 'class', 'attackType', 'attackID', 'attackDescription']
    df = pd.read_csv(filename, names=column_names, header=0)
    print(f"Total records loaded: {len(df)}")
    print(f"Available columns: {list(df.columns)}")
    if normal_filter:
        df = df[df['class'] == 'normal']
        print(f"Filtered to normal records: {len(df)}")
    if len(df) == 0:
        print("No data found after filtering!")
        return None
    total_records = len(df)
    print(f"Total records for baseline: {total_records}\n")
    categorical_columns = ['Proto', 'Src IP Addr', 'Dst IP Addr', 'Src Pt', 'Dst Pt', 'Flags', 'Tos', 'class']
    if 'duration' in df.columns:
        df['duration Binned'] = pd.cut(df['duration'].fillna(0), bins=[0, 1, 10, float('inf')], labels=['short', 'medium', 'long'])
        categorical_columns.append('duration Binned')
    df['Src Pt Binned'] = pd.cut(df['Src Pt'], bins=[0, 1024, float('inf')], labels=['low', 'high'])
    df['Dst Pt Binned'] = pd.cut(df['Dst Pt'], bins=[0, 1024, float('inf')], labels=['low', 'high'])
    categorical_columns.extend(['Src Pt Binned', 'Dst Pt Binned'])
    baseline_data = []
    for column in categorical_columns:
        if column not in df.columns:
            continue
        print(f"Analyzing: {column}")
        values = df[column].astype(str).tolist()
        frequency = Counter(values)
        for value, count in frequency.items():
            if value == 'nan':
                continue
            percentage = (count / total_records) * 100
            baseline_data.append({
                'Column': column,
                'Value': value,
                'Baseline_Count': count,
                'Baseline_Percentage': round(percentage, 2),
                'Total_Records': total_records,
                'Status': 'Normal' if percentage >= 5 else 'Rare'
            })
    if not baseline_data:
        print("No baseline data generated!")
        return None
    baseline_df = pd.DataFrame(baseline_data)
    baseline_df = baseline_df.sort_values(['Column', 'Baseline_Count'], ascending=[True, False])
    baseline_df.to_csv(baseline_output, index=False)
    print(f"\n{'='*70}")
    print(f"✓ Baseline created and saved to: {baseline_output}")
    print(f"{'='*70}\n")
    print("BASELINE SUMMARY (Top 20 rows):")
    print("-"*70)
    print(baseline_df.head(20).to_string(index=False))
    return baseline_df

def detect_anomalies(new_logfile, baseline_file="cidds_baseline.csv", output_file="cidds_anomaly_report.csv", threshold=20, nrows=1000):
    print(f"\nDetecting anomalies in: {new_logfile}")
    print("="*70)
    baseline_df = pd.read_csv(baseline_file)
    column_names = ['Date first seen', 'duration', 'Proto', 'Src IP Addr', 'Src Pt', 'Dst IP Addr', 'Dst Pt', 'Packets', 'Bytes', 'Flows', 'Flags', 'Tos', 'class', 'attackType', 'attackID', 'attackDescription']
    new_df = pd.read_csv(new_logfile, names=column_names, header=0, low_memory=False, nrows=nrows)
    print(f"Available columns: {list(new_df.columns)}")
    total_new_records = len(new_df)
    print(f"New records to analyze: {total_new_records}\n")
    if total_new_records == 0:
        print("No new data found!")
        return []
    for col in ['Src Pt', 'Dst Pt', 'duration']:
        new_df[col] = pd.to_numeric(new_df[col], errors='coerce').fillna(0).astype(float)
    new_df['Src Pt Binned'] = pd.cut(new_df['Src Pt'], bins=[0, 1024, float('inf')], labels=['low', 'high'])
    new_df['Dst Pt Binned'] = pd.cut(new_df['Dst Pt'], bins=[0, 1024, float('inf')], labels=['low', 'high'])
    new_df['duration Binned'] = pd.cut(new_df['duration'].fillna(0), bins=[0, 1, 10, float('inf')], labels=['short', 'medium', 'long'])
    categorical_columns = ['Proto', 'Src IP Addr', 'Dst IP Addr', 'Src Pt', 'Dst Pt', 'Flags', 'Tos', 'class', 'Src Pt Binned', 'Dst Pt Binned', 'duration Binned']
    anomalies = []
    for column in categorical_columns:
        if column not in new_df.columns:
            continue
        values = new_df[column].astype(str).tolist()
        current_freq = Counter(values)
        for value, count in current_freq.items():
            if value == 'nan':
                continue
            current_percentage = (count / total_new_records) * 100
            baseline_row = baseline_df[(baseline_df['Column'] == column) & (baseline_df['Value'] == value)]
            if baseline_row.empty:
                anomalies.append({
                    'Column': column,
                    'Value': value,
                    'Current_Count': count,
                    'Current_Percentage': round(current_percentage, 2),
                    'Baseline_Percentage': 0,
                    'Deviation': round(current_percentage, 2),
                    'Anomaly_Type': 'New Value',
                    'Severity': 'High' if current_percentage > 10 else 'Medium'
                })
            else:
                baseline_percentage = baseline_row.iloc[0]['Baseline_Percentage']
                deviation = abs(current_percentage - baseline_percentage)
                if deviation > threshold:
                    anomaly_type = 'Frequency Deviation'
                    if new_df[(new_df[column] == value) & (new_df['class'] != 'normal')].shape[0] > 0:
                        anomaly_type += ' (Potential Attack)'
                    anomalies.append({
                        'Column': column,
                        'Value': value,
                        'Current_Count': count,
                        'Current_Percentage': round(current_percentage, 2),
                        'Baseline_Percentage': baseline_percentage,
                        'Deviation': round(deviation, 2),
                        'Anomaly_Type': anomaly_type,
                        'Severity': 'High' if deviation > 50 else 'Medium'
                    })
    if anomalies:
        anomaly_df = pd.DataFrame(anomalies)
        anomaly_df = anomaly_df.sort_values('Deviation', ascending=False)
        anomaly_df.to_csv(output_file, index=False)
        print(f"⚠ {len(anomalies)} ANOMALIES DETECTED!")
        print(f"Anomaly report saved to: {output_file}\n")
        print("ANOMALY REPORT (Top 10):")
        print("-"*70)
        print(anomaly_df.head(10).to_string(index=False))
    else:
        print("✓ No anomalies detected - behavior matches baseline!")
    return anomalies

def main():
    training_file = "CIDDS-001-internal-week1.csv"
    baseline = create_baseline(training_file, "cidds_baseline.csv", normal_filter=True)
    test_file = "CIDDS-001-internal-week2.csv"
    anomalies = detect_anomalies(test_file, "cidds_baseline.csv", "cidds_anomaly_report.csv", threshold=20)
    print("\n" + "="*70)
    print("CIDDS ANOMALY ANALYSIS COMPLETE!")
    print("="*70)

if __name__ == "__main__":
    main()
