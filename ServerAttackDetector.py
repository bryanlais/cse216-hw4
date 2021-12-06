import io, os, datetime, csv

class ServerAttackDetector:
    def __init__(self, path):
        self.path = path
            
    def detect(self):
        a = 1
        with open(self.path, 'r') as csvfile:
            lines = csvfile.readlines()
            lines.pop(0) #Removes the header of the csv.
            prev_sus_udp = 0
        for i in range(0,len(lines)):
            b = lines[i] #The string of the entire row.
            arr = lines[i].split(",")
            pass4 = 0 
            #4) Checks if the previous communication using UDP (and marked "suspicious") happened within one second.
            if(prev_sus_udp == 0):
                pass
            else:
                #Splitting 2017-03-21 21:21:43.508 into ["2017-03-21","21:21:43.508"]
                timeArr0 = prev_sus_udp[0].split(" ")
                timeArr1 = arr[0].split(" ")
                if(timeArr0[0] == timeArr1[0]):
                    #Splitting "21:21:43.508" into an array like [21,21,43.508]
                    time0 = timeArr0[1].split(":") 
                    time1 = timeArr1[1].split(":")
                    if(time0[0] == time1[0] and time0[1] == time1[1]):
                        #Splitting 43.508 into ["43","508"]
                        time00 = time0[2].split(".")
                        time11 = time1[2].split(".")
                        #Converting ["43","508"] into 43508. 
                        time_0 = float(time00[0]) * 1000 + float(time00[1])
                        time_1 = float(time00[0]) * 1000 + float(time00[1])
                        #The time diff between both numbers.
                        time_diff = abs(time_0-time_1)
                        #Checking if difference between 43508 and and another number is between 0 and 999.
                        if(time_diff >= 0 and time_diff < 1):
                            pass4 = 1
            #1) Checks Protocol to be UDP
            if(arr[2].strip() != 'UDP'):
                a += 1
                continue
            #2) Checks class to be suspicious
            if(arr[12].strip() != 'suspicious'):
                a += 1
                continue
            prev_sus_udp = lines[i].split(",")
            #3) Checks if the duration is less than a millisecond.
            if(float(arr[1].strip()) >= 1):
                a += 1
                continue
            if(pass4 == 1):
                return (a,b)
            else:
                a += 1
                continue
            
a = ServerAttackDetector('hw4testfile.csv')
print(a.detect())