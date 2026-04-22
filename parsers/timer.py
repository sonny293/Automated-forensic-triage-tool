"""
Timer that converts overall time into sec, min, hours
rounds secs to 3 decimal places

inputs:
start - time of start of program
end - time at end of program

returns:
total time measured
secs(round 3), mins, hours.
"""


def timer(start, end):
    elapsed = end - start
    hours = int(elapsed // 3600)
    remaining = elapsed % 3600
    minutes = int(remaining // 60)
    seconds = remaining % 60
    return round(seconds, 3), minutes, hours
