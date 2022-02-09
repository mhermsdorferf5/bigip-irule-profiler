# Basic F5 iRule Profiling log parser.
# F5's rule profiling engine simply logs start/stop time in microseconds for various actions.
# This tool matches 'exit/end' log event to it's 'entry/start' event then calculates the execution time.

import subprocess
import json
import math

# Some basic subroutines for math operations...
# Using simple python2 math, since that's all we have on the BIG-IP
def mean(items):
    n = len(items)
    mean = sum(items) / n
    return mean
def variance(items, ddof=0):
    n = len(items)
    mean = sum(items) / n
    return sum((x - mean) ** 2 for x in items) / (n - ddof)
def stdev(data):
    var = variance(data)
    std_dev = math.sqrt(var)
    return round(std_dev,2)

# subroutines for stats generation, takes in a dictionary, 
# returns the same dictionary with stats added.
def generateStats(dictionary):
    dictionary["stats"] = {}
    eventList = []
    eventTotal = []
    eventMean = []
    for event in dictionary["events"]:
        dictionary["stats"][event] = {}
        dictionary["stats"][event]["executions"] = len(dictionary["events"][event])
        dictionary["stats"][event]["mean_time"] = mean(dictionary["events"][event])
        dictionary["stats"][event]["std_dev"] = stdev(dictionary["events"][event])
        dictionary["stats"][event]["min_time"] = min(dictionary["events"][event])
        dictionary["stats"][event]["max_time"] = max(dictionary["events"][event])
        dictionary["stats"][event]["total_time"] = sum(dictionary["events"][event])/1000
        eventList.append(event)
        eventTotal.append(sum(dictionary["events"][event])/1000)
        eventMean.append(mean(dictionary["events"][event]))
    dictionary["stats"]["eventsSortedByMean"] = [x for _,x in sorted(zip(eventMean,eventList),reverse=True)]
    dictionary["stats"]["eventsSortedByTotal"] = [x for _,x in sorted(zip(eventTotal,eventList),reverse=True)]
    return dictionary

def reportStats(dictionary):
    sectionHeading = " Data for Occurrance Type: " + dictionary["occurrence_type"] + " "
    linePadding = ((80-len(sectionHeading))/2) * "="
    output = ("="*80) + "\n"
    output = output + linePadding + sectionHeading + linePadding + "\n"
    output = output + ("="*80) + "\n"
    output = output + "Occurrences sorted by total time: " + ", ".join(dictionary["stats"]["eventsSortedByMean"]) + "\n\n"
    output = output + "Occurrences sorted by mean time: " + ", ".join(dictionary["stats"]["eventsSortedByTotal"]) + "\n"
    output = output + "\n========================================\n"
    for event in dictionary["stats"]["eventsSortedByMean"]:
        executions = str(dictionary["stats"][event]["executions"])
        mean_time  = str(dictionary["stats"][event]["mean_time"])
        std_dev    = str(dictionary["stats"][event]["std_dev"])
        min_time   = str(dictionary["stats"][event]["min_time"])
        max_time   = str(dictionary["stats"][event]["max_time"])
        total_time = str(dictionary["stats"][event]["total_time"])
        output = output + "Type: " + dictionary["occurrence_type"] + "\tOccurrance: "+ event
        output = output + "\n\tExecution Count: " + executions
        output = output + "\n\tTotal Time: " + total_time + "ms"
        output = output + "\n\tMean Execution Time:\t" + mean_time + "us"
        output = output + "\n\tStandard Deviation:\t"  + std_dev 
        output = output + "\n\tMax Execution Time:\t"  + max_time 
        output = output + "\n\tMin Execution Time:\t"  + min_time
        output = output + "\n========================================\n"
    output = output + ("="*80) + "\n"
    output = output + ("="*80) + "\n\n"
    return output

# subroutine to parse occurrences into dictionaries
def parseLogOccurrences(occurrenceType,occurrenceList):
    ## Now we'll loop though the event list and look for exit events to match up.
    # Note that we need to keep track of our own index, so that once we find an exit event
    # we can reverse the order of the list and look for the next matching entry.
    occurrence_index = 0
    # durration dictionary, we store a list per event occurrence:
    entryString = occurrenceType + "_ENTRY"
    exitString = occurrenceType + "_EXIT"
    rp_occurrence_durration = { "occurrence_type": occurrenceType }
    rp_occurrence_durration["events"] = {}
    for entry in occurrenceList:
        # If it's an exit event...
        if entry["occurrence_type"] == exitString:
            open_occurrence_index = 0
            open_events = []
            # Now we need to search from our current index back in history to find the next open event.
            # Create a range from our current index... (0 - currentIndex)
            # Then reverse that, and start looping on that index counting down.
            for index in reversed(range(occurrence_index)):
                # Get the log/dict entry associated with this index:
                open_entry = occurrenceList[index]
    
                # Check if the log/dict entry matches with our open event:
                # The following should match: occurrence, tuples, flowid, tmm pid.
                # but of course it needs to be the entry event:
                if open_entry["occurrence_type"] == entryString and open_entry["occurrence"] == entry["occurrence"] \
                and open_entry["local_tuple"] == entry["local_tuple"] and open_entry["remote_tuple"] == entry["remote_tuple"] \
                and open_entry["flow_id"] == entry["flow_id"] and open_entry["tmm_pid"] == entry["tmm_pid"]:
    
                    # For matches, calculate the durration time:
                    time = int(entry["timestamp"]) - int(open_entry["timestamp"])
                    # Shove said durration time into our event durration dict/list:
                    if str(open_entry["occurrence"]) in rp_occurrence_durration["events"].keys():
                        # If the key already exists, then append:
                        rp_occurrence_durration["events"][str(open_entry["occurrence"])].append(time)
                    else:
                        # otherwise, create the key & list, then append:
                        rp_occurrence_durration["events"][str(open_entry["occurrence"])] = []
                        rp_occurrence_durration["events"][str(open_entry["occurrence"])].append(time)
                    # once we find the entry, we can break out and be done:
                    break
        # increment the index:
        occurrence_index += 1
    return(rp_occurrence_durration)

# Grep command to get the log lines out of a file:
# This should be a good bit faster than opening the log file and finding the RP log file entries within python.
#cmd_grep_rp_loglines='''/bin/grep -P "info tmm\[\d+\]: \d+,RP_" /var/log/ltm'''
cmd_grep_rp_loglines='''/bin/grep -P "info tmm\[\d+\]: \d+,RP_" /mnt/c/Users/hermsdorfer/ltm'''
#cmd_grep_rp_loglines='''/bin/grep -P "HTTP_REQUEST.*10.1.1.11,58424,0,10.1.10.9,8443,0" /mnt/c/Users/hermsdorfer/ltm'''
rp_loglines = subprocess.check_output(cmd_grep_rp_loglines, shell=True)

# Initialize Variables.
rp_events = []
rp_cmds = []
log_line_order = ["month", "day", "time", "hostname", "severity", "process", "message"]
profile_msg_order = ["timestamp", "occurrence_type", "virtual_server", "occurrence", "tmm_pid", "flow_id", "remote_ip", "remote_port", "remote_rd", "local_ip", "local_port", "local_rd"]

# Parse the log file entries and load the log messages into dictionary
# then store the dicts in a list (order matters)
for line in rp_loglines.splitlines():
    # We don't care to track variable modification with this tool
    # parsing the var mods also is a bit more complex, so we'll just skip those lines.
    if "RP_VAR_MOD" in line:
        continue
    # Split the log line via whitespace:
    split_line = line.split()
    # For RP logs, our message will always be the 6th element (starting from zero), in some cases the RP log message has a space (cmd/cmd-vm)
    rp_message = split_line[6]
    if len(split_line) > 7:
        rp_message = split_line[6] + split_line[7]
    # Next split the RP message based on commas:
    details = rp_message.split(',')
    details = [x.strip() for x in details]
    # Store the message data in a dictionary, using the order defined above.
    structure = {key:value for key, value in zip(profile_msg_order, details)}
    # We'll create a single dictionary entry for the 3tuple local & remote ip/port/datagroup fields.
    # This simplifies our conditionals when we go matchign, perhaps not the most performant, but easier to grock.
    if structure["remote_ip"]:
        structure["local_tuple"] = structure["local_ip"] + "%" + structure["local_rd"] + ":" + structure["local_port"]
        structure["remote_tuple"] = structure["remote_ip"] + "%" + structure["remote_rd"] + ":" + structure["remote_port"]
    # Shove iRule EVENT data into the rp_events dictonary:
    if "RP_EVENT_" in structure["occurrence_type"]:
        rp_events.append(structure)
    # Shove iRule command data into the rp_cmds dictonary:
    if "RP_CMD_" in structure["occurrence_type"]:
        rp_cmds.append(structure)

# Parse the logs and create dictionaries of occurrence durrations
rp_event_durration = parseLogOccurrences("RP_EVENT",rp_events)
rp_cmd_durration = parseLogOccurrences("RP_CMD",rp_cmds)
rp_cmd_vm_durration = parseLogOccurrences("RP_CMD_VM",rp_cmds)

# Generate stats using the dictionaries and occurrence durrations
rp_event_durration = generateStats(rp_event_durration)
rp_cmd_durration = generateStats(rp_cmd_durration)
rp_cmd_vm_durration = generateStats(rp_cmd_vm_durration)

# Now time to report our findings.
print(reportStats(rp_event_durration))
print(reportStats(rp_cmd_durration))
print(reportStats(rp_cmd_vm_durration))
exit(0)
