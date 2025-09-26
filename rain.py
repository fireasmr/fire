H2. source="log new1.csv" sourcetype="csv"  
| rex field=_raw max_match=0 "Account Name:\s*(?<users>\S+)"   
| eval user = mvfilter(users!="-")   
| where 'Event ID'="4624" 
| search user IN ("C3570", "C6279","20pa01-05")
| eval _time = strptime("Date and Time", "%m/%d/%Y %H:%M")


H3. source="log new1.csv" sourcetype="csv"  
| rex field=_raw max_match=0 "Account Name:\s*(?<users>\S+)"   
| eval user = mvfilter(users!="-")   
| where 'Event ID'="4625"
| stats count as failed_attempts by user
| where failed_attempts > 4
| table user, failed_attempts


H4. source="log new1.csv" sourcetype="csv"  
| rex field=_raw max_match=0 "Account Name:\s*(?<users>\S+)"   
| eval user = mvfilter(users!="-")   
| rex field=message "Logon ID:\s*(?<LogonID>\S+)"
| where ('Event ID'="4624" OR 'Event ID'="4634" OR 'Event ID'="4647")
| sort _time
| transaction LogonID maxspan=1h keepevicted=true startswith=('Event ID'="4624") endswith=('Event ID'="4634" OR 'Event ID'="4647")
| where duration < 600
| table _time, user, LogonID, duration, 'Event ID'

H6. source="log new1.csv" sourcetype="csv"  
| rex field=_raw max_match=0 "Account Name:\s*(?<users>\S+)"   
| eval user = mvfilter(users!="-")   
| where 'Event ID'="4624"
| eval day_of_week = strftime(_time, "%w")
| eval hour_of_day = strftime(_time, "%H")
| where (day_of_week=0 OR day_of_week=6) 
    OR (day_of_week>=1 AND day_of_week<=5 AND (hour_of_day < 8 OR hour_of_day >= 11))
| table _time, user, 'Event ID', day_of_week, hour_of_day, "Date and Time"



h1.source="log new1.csv" sourcetype="csv"   
| rex field=_raw max_match=0 "Account Name:\s*(?<users>\S+)"   
| eval user = mvfilter(users!="-")
| rex field=_raw "Source Network Address:\s*(?<IpAddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| where 'Event ID'="4624" OR 'Event ID'="4625"
| sort _time
| streamstats window=10 count(eval('Event ID'="4625")) as recent_failed_attempts by user
| where recent_failed_attempts > 2 AND 'Event ID'="4624"

------------ca1--------------


Count Connections by User (stats)
source="network_data.csv" 
| stats count as Connection_Count by User
| sort -Connection_Count

Total Packet Size by Destination IP (stats)
source="network_data.csv" 
| stats sum(packet_size) as Total_Packet_Size by dest_ip
| sort -Total_Packet_Size

Average Packet Size by User and Destination IP (stats)
source="network_data.csv"
| stats avg(packet_size) as Avg_Packet_Size by User, dest_ip
| eval Avg_Packet_Size=round(Avg_Packet_Size, 2)
| sort User, dest_ip

Add Total Connections to Each Event (eventstats)
source="network_data.csv"
| eventstats count as Total_User_Connections by User
| table User, client_ip, dest_ip, packet_size, Total_User_Connections
| sort User, Timestamp

Connections Over Time by Destination IP (timechart)
source="network_data.csv" 
| eval _time=strptime(Timestamp, "%m/%d/%Y %H:%M")
| timechart span=1d count by dest_ip


Overall Packet Size Variation
source="network_data.csv" 
| stats min(packet_size) as Min_Size, max(packet_size) as Max_Size, avg(packet_size) as Avg_Size, stdev(packet_size) as Std_Dev_Size
| eval Range=Max_Size - Min_Size
| eval Avg_Size=round(Avg_Size, 2), Std_Dev_Size=round(Std_Dev_Size, 2)
| table Min_Size, Max_Size, Range, Avg_Size, Std_Dev_Size

Packet Size Variation group by user
source="network_data.csv" 
| stats min(packet_size) as Min_Size, max(packet_size) as Max_Size, avg(packet_size) as Avg_Size, stdev(packet_size) as Std_Dev_Size by User
| eval Range=Max_Size - Min_Size
| eval Avg_Size=round(Avg_Size, 2), Std_Dev_Size=round(Std_Dev_Size, 2)
| sort -Std_Dev_Size
| table User, Min_Size, Max_Size, Range, Avg_Size, Std_Dev_Size



source="network_data.csv" host="AMCS-SCL-33" sourcetype="csv" 
| eval length = len(packet_size)
| stats min(packet_size) as Min_Size, max(packet_size) as Max_Size, avg(packet_size) as Avg_Size, stdev(packet_size) as Std_Dev_Size, var(packet_size) as Variance_packet_Size, median(packet_size) as Median_packet_size by EventID


--------------appu-----------

Class distribution
source="ds.csv" 
| stats count by class
| sort -count

Inbound vs outbound traffic visualization
source="ds.csv"
| timechart sum(ifInOctets11) AS Total_Inbound sum(ifOutOctets11) AS Total_Outbound

TCP Performance - retransmission rate [formula is applied]
source="ds.csv"
| eval RetransRate = (tcpRetransSegs/tcpOutSegs)*100
| timechart avg(RetransRate) AS Avg_Retransmission_Percentage

Established Connections Trend - just visualizing active tcp connections
source="ds.csv"
| timechart sum(tcpCurrEstab) AS Active_TCP_Connections

Error Analysis - Input vs Output Discards
source="ds.csv"
| timechart sum(ifInDiscards11) AS In_Discards sum(ifOutDiscards11) AS Out_Discards

ICMP Analysis- Message Types Distribution
source="ds.csv"
| stats sum(icmpInMsgs) AS In_Msgs sum(icmpOutMsgs) AS Out_Msgs sum(icmpInDestUnreachs) AS In_Unreach sum(icmpOutDestUnreachs) AS Out_Unreach

Class trend over time
source="ds.csv"
| timechart count by class

Anomalous Flow Trends (e.g., PKT_SIZE for "normal" vs. "malicious" Class)
[first find avg packetsize by writing logic then visualize it]
source="ds.csv"
| eval In_AvgPktSize = ifInOctets11/ifInUcastPkts11, Out_AvgPktSize = ifOutOctets11/ifOutUcastPkts11
| stats avg(In_AvgPktSize) AS Avg_In_Size avg(Out_AvgPktSize) AS Avg_Out_Size BY class

Network Traffic Volume Analysis
source="network_data.csv" 
| chart sum(packet_size) as "Total Bytes" by User
| sort - "Total Bytes"

Security Analysis
Query: Identify users with unusual network behavior (connections outside business hours)
source="network_data.csv" 
| eval timestamp_epoch=strptime(Timestamp, "%m/%d/%Y %H:%M")
| eval hour=strftime(timestamp_epoch, "%H")
| where hour < "08" OR hour > "18"
| stats count as "After Hours Connections" by User
| sort - "After Hours Connections"

User Behavior Profiling
Query: Create user activity profiles
source="network_data.csv" 
| stats count as connections, 
        avg(packet_size) as avg_packet_size,
        max(packet_size) as max_packet_size,
        dc(dest_ip) as unique_destinations
        by User
| sort - connections


Network Utilization
Query: Peak usage times identification
source="network_data.csv" 
| eval timestamp_epoch=strptime(Timestamp, "%m/%d/%Y %H:%M")
| eval hour=strftime(timestamp_epoch, "%H")
| sort hour
| stats sum(packet_size) as "traffic hours" by hour


Peak anomalous packets
source="network_data.csv" 
| eventstats avg(packet_size) as avg_size, stdev(packet_size) as std_dev
| eval upper_bound=avg_size + (2*std_dev)
| eval lower_bound=avg_size - (2*std_dev)
| where packet_size > upper_bound OR packet_size < lower_bound
| chart count by User packet_size
 Heatmap but won’t output as it won’t be installed


EventID vs Timestamp for Specific User (As Requested)
source="network_data.csv" 
| where User="david"
| eval timestamp_epoch=strptime(Timestamp, "%m/%d/%Y %H:%M")
| eval formatted_time=strftime(timestamp_epoch, "%m/%d %H:%M")
| chart values(EventID) over formatted_time
| sort formatted_time
----------visualization----------

You need this when: Your question has two parts, like "Find all network events from the top 5 most active users." You first need to find the top users, then find their events.
Scenario: You want to see the detailed event data, but only for the source IPs that are responsible for the top 3 highest traffic (ifInOctets) events.
source="all_data (3).csv"
| eval columns = split(_raw, ",")
| eval src_ip = mvindex(columns, <index_for_src_ip>)
| eval ifInOctets = tonumber(mvindex(columns, <index_for_ifInOctets>))
| where [ search source="all_data (3).csv"
            | eval columns = split(_raw, ",")
            | eval src_ip = mvindex(columns, <index_for_src_ip>)
            | eval ifInOctets = tonumber(mvindex(columns, <index_for_ifInOctets>))
            | sort 3 -ifInOctets
            | fields src_ip ]
| table _time, src_ip, ifInOctets
