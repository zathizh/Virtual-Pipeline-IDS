## Attack Name                        Numbers         Category
## ---------------------------------------------------------
## Setpoint Attack			1-2		MPCI
## PID Gain Attack			3-4		MPCI
## PID Reset Rate Attack		5-6		MPCI
## PID Rate Attack			7-8		MPCI
## PID Deadband Attack		        9-10		MPCI
## PID Cycle Time Attack		11-12		MPCI
##
## Pump Attack				13		MSCI
## Solenoid Attack 			14 		MSCI
## System Mode Attack			15		MSCI
## Critical Condition Attack		16-17		MSCI
##
## Bad CRC Attack			18		DOS
##
## Clean Registers Attack		19		MFCI
##
## Device Scan Attack			20		Recon
##
## Force Listen Attack			21		MFCI
## Restart Attack			22		MFCI
##
## Read Id Attack			23		Recon
## Function Code Scan Attack		24		Recon
##
## Rise/Fall Attack			25-26		CMRI
## Slope Attack 			27-28		CMRI
##
## Random Value Attack	        	29-31		NMRI
## Negative Pressure Attack		32		NMRI
##
## Fast Attack				33-34		CMRI
## Slow Attack				35		CMRI

import time, sys

## Mapping Attacks and Attack categories 
attack = { 1:("Setpoint Attack", "MPCI"), 2:("Setpoint Attack", "MPCI"),\
           3:("PID Gain Attack", "MPCI"), 4:("PID Gain Attack", "MPCI"),\
           ## PID Reset Rate Attack
           5:("PID Rst Rate Attack", "MPCI"), 6:("PID Rst Rate Attack", "MPCI"),\
           7:("PID Rate Attack", "MPCI"), 8:("PID Rate Attack", "MPCI"),\
           9:("PID Deadband Attack", "MPCI"), 10:("PID Deadband Attack", "MPCI"),\
           11:("PID Cycle Time Attack", "MPCI"), 12:("PID Cycle Time Atta.", "MPCI"),\
           13:("Pump Attack", "MSCI"),\
           14:("Solenoid Attack", "MSCI"),\
           15:("System Mode Attack", "MSCI"),\
           ## Critical Condition Attack
           16:("Critical Cond. Attack", "MSCI"), 17:("Critical Cond. Attack", "MSCI"),\
           18:("Bad CRC Attack", "DOS"),\
           19:("Clean Registers Attack", "MFCI"),\
           20:("Device Scan Attack", "Recon"),\
           21:("Force Listen Attack", "MFCI"),\
           22:("Restart Attack", "MFCI"),\
           23:("Read Id Attack", "Recon"),\
           24:("Function Code Scan Attack", "Recon"),\
           25:("Rise/Fall Attack", "CMRI"), 26:("Rise/Fall Attack", "CMRI"),\
           27:("Slope Attack", "CMRI"), 28:("Slope Attack", "CMRI"),\
           29:("Random Value Attack", "NMRI"), 30:("Random Value Attack", "NMRI"), 31:("Random Value Attack", "NMRI"),\
           32:("Negative Pressure Attack", "NMRI"),\
           33:("Fast Attack", "CMRI"), 34:("Fast Attack", "CMRI"),\
           35:("Slow Attack", "CMRI") }

attack_categroy = { 0:("Normal", "NORMAL"),\
                    1:("Naive Malicious Response Injection", "NMRI"),\
                    2:("Complex Malicious Response Injection", "CMRI"),\
                    3:("Malicious State Command Injection", "MCSI"),\
                    4:("Malicious Parameter Command Injection", "MPCI"),\
                    5:("Malicious Function Code Injection", "MFCI"),\
                    6:("Denial of Service", "DOS"),\
                    7:("Reconnaissance", "RECON") }

## MODBUS Function Codes
modbus_function = { 0:"Unknown",\
                    1:"Read Coil",\
                    2:"Read Discrete Input",\
                    3:"Read Holding Registers",
                    4:"Read Input Registers",\
                    5:"Write Single Coil",\
                    ## Write Single Holding Registers
                    6:"Wr Single Holding Reg",\
                    7:"Read Exception Status",\
                    8:"Diagnostic",\
                    9:"Program 484",\
                    10:"Poll 484",\
                    11:"Get Com Event Counter",\
                    12:"Get Com Event Log",\
                    13:"Program Controller",\
                    14:"Poll Controller",\
                    15:"Write Multiple Coils",\
                    ## Wr Multiple Holding Registers
                    16:"Wr Multi. Holding Reg",\
                    17:"Report Slace ID",\
                    ## Read Device Identification
                    43:"Rd Dev Identification",\
                    128:"Duplicate Station",\
                    }

## statistical informations
attack_stat={x:0 for x in range(23)}

## total # requests
total_counter = 0

## Structure of gas pipeline data object 
class ARFF:
        ##
        ## @relation gas
        ##
        ## @attribute 'address' real
        ## @attribute 'function' real
        ## @attribute 'length' real
        ## @attribute 'setpoint' real
        ## @attribute 'gain' real
        ## @attribute 'reset rate' real
        ## @attribute 'deadband' real
        ## @attribute 'cycle time' real
        ## @attribute 'rate' real
        ## @attribute 'system mode' real
        ## @attribute 'control scheme' real
        ## @attribute 'pump' real
        ## @attribute 'solenoid' real
        ## @attribute 'pressure measurement' real
        ## @attribute 'crc rate' real
        ## @attribute 'command response' {0,1}
        ## @attribute 'time' real
        ## @attribute 'binary result' {'0','1'}
        ## @attribute 'categorized result' { i for i in range(1,8) }
        ## @attribute 'specific result' { i for i in range(1,36) }
        ## @data
        ##

	def __init__(self, raw):
		raw = raw.split(',')
		self.addr = raw[0]                      ## network
		self.func = raw[1]                      ## command payload
		self.leng = raw[2]                      ## network
		self.setpoint = raw[3]                  ## command payload

		## PID Fields
		self.pid_gain = raw[4]                  ## command payload
		self.pid_rst_rate = raw[5]              ## command payload
		self.pid_deadband = raw[6]              ## command payload
		self.pid_cycle_tm = raw[7]              ## command payload
		self.pid_rate = raw[8]                  ## command payload

		## automatic(2), manual(1), off(0)
		self.sys_mode = raw[9]                  ## command payload

		## pump(0), solenoid(1)
		self.ctr_schm = raw[10]                 ## command payload

		## pump control on(1), off(0)
		self.pmp = raw[11]                      ## command payload

		## opend (1), closed(0)
		self.solenoid = raw[12]                 ## command payload
		self.pressure = raw[13]                 ## response payload
		self.crc = int(raw[14])                 ## network

		## cmnd(1), response(0)
		self.cmd_res = int(raw[15])             ## network
		self.tm = float(raw[16])                ## network

		## attack(1), normal(0)
		self.bin_rslt = int(raw[17])            ## lable

		## attack category (0-7)
		self.cat_rslt = int(raw[18])            ## lable

		## specific attack (0-35)
		self.spc_rslt = int(raw[19])            ## lable

## converting the timpestamp
def timestampConverter(timestamp):
        return time.strftime("%d %b %Y %H:%M:%S", time.gmtime(timestamp))

## check for attacking vector
def check_attack(spc_rslt):
        if spc_rslt > 0 and spc_rslt < 36:
                return 1
        else:
                return 0

## check system mode
def system_mode(sys_mode):
        if not sys_mode.isdigit():
                return "None"
        elif int(sys_mode) == 0:
                return "OFF"
        elif int(sys_mode) == 1:
                return "MANUAL"
        elif int(sys_mode) == 2:
                return "AUTO"
        else:
                return "None"

## check control scheme
def control_scheme(ctr_schm):
        if not ctr_schm.isdigit():
                return "None"
        elif int(ctr_schm) == 0:
                return "PUMP"
        elif int(ctr_schm) == 1:
                return "SOLENOID"
        else:
                return "None"

## check pump status
def pump(pmp):
        if not pmp.isdigit():
                return "None"
        elif int(pmp) == 0:
                return "OFF"
        elif int(pmp) == 1:
                return "ON"
        else :
                return "None"

# check solenoid status
def solenoid(solenoid):
        if not solenoid.isdigit():
                return "None"
        elif int(solenoid) == 0:
                return "CLOSED"
        elif int(solenoid) == 1:
                return "OPENED"
        else:
                return "None"

## check command status
def command(cmd_res):
        if cmd_res == 0:
                return "RESP"
        elif cmd_res == 1:
                return "CMND"
        else:
                return "None"

def modbus_func(func):
        if not func.isdigit():
                return "None"
        elif int(func) in modbus_function.keys():
                return modbus_function[int(func)]
        else:
                return "Unknown"

## print informations
def printer(data):
        print(timestampConverter(data.tm), end="")
        print(" ", end="")
        print(data.addr, end=""),
        print(" Attack :[",end="")
        print(attack[data.spc_rslt][0],end="")
        print("] Categ. :[",end="")
        print(attack_categroy[data.cat_rslt][1],end="")
        print("] MODBUS Func. :[",end="")
        print(modbus_func(data.func),end="")
        print("] Sys. Mode :[",end="")
        print(system_mode(data.sys_mode),end="")
        print("] Control Scheme :[",end="")
        print(control_scheme(data.ctr_schm),end="")
        print("] Pump :[",end="")
        print(pump(data.pmp),end="")
        print("] Solenoid :[",end="")
        print(solenoid(data.solenoid),end="")
        print("] Command :[",end="")
        print(command(data.cmd_res),end="")
        print("]")


## Counts specified attacks
def statistics(spc_rslt):
        if spc_rslt == 1 or spc_rslt == 2:
                attack_stat[0] = attack_stat[0] + 1
        elif spc_rslt == 3 or spc_rslt == 4:
                attack_stat[1] = attack_stat[1] + 1
        elif spc_rslt == 5 or spc_rslt == 6:
                attack_stat[2] = attack_stat[2] + 1
        elif spc_rslt == 7 or spc_rslt == 8:
                attack_stat[3] = attack_stat[3] + 1
        elif spc_rslt == 9 or spc_rslt == 10:
                attack_stat[4] = attack_stat[4] + 1
        elif spc_rslt == 11 or spc_rslt == 12:
                attack_stat[5] = attack_stat[5] + 1
        elif spc_rslt == 13:
                attack_stat[6] = attack_stat[6] + 1
        elif spc_rslt == 14:
                attack_stat[7] = attack_stat[7] + 1
        elif spc_rslt == 15:
                attack_stat[8] = attack_stat[8] + 1
        elif spc_rslt == 16 or spc_rslt == 17:
                attack_stat[9] = attack_stat[9] + 1
        elif spc_rslt == 18:
                attack_stat[10] = attack_stat[10] + 1
        elif spc_rslt == 19:
                attack_stat[11] = attack_stat[11] + 1
        elif spc_rslt == 20:
                attack_stat[12] = attack_stat[12] + 1
        elif spc_rslt == 21:
                attack_stat[13] = attack_stat[13] + 1
        elif spc_rslt == 22:
                attack_stat[14] = attack_stat[14] + 1
        elif spc_rslt == 23:
                attack_stat[15] = attack_stat[15] + 1
        elif spc_rslt == 24:
                attack_stat[16] = attack_stat[16] + 1
        elif spc_rslt == 25 or spc_rslt == 26:
                attack_stat[17] = attack_stat[17] + 1
        elif spc_rslt == 27 or spc_rslt == 28:
                attack_stat[18] = attack_stat[18] + 1
        elif spc_rslt == 29 or spc_rslt == 30 or spc_rslt == 31:
                attack_stat[19] = attack_stat[19] + 1
        elif spc_rslt == 32:
                attack_stat[20] = attack_stat[20] + 1
        elif spc_rslt == 33 or spc_rslt == 34:
                attack_stat[21] = attack_stat[21] + 1
        elif spc_rslt == 35:
                attack_stat[22] = attack_stat[22] + 1


## print the statistic informations
def statistic_printer():
        print("---------------------------------------------------------")
        print("  Setpoint Attacks \t\t: ",end="")
        print("%5s" % attack_stat[0],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[0])/total_counter*100),end="")
        print("%")
        print("  PID Gain Attacks \t\t: ",end="")
        print("%5s" % attack_stat[1],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[1])/total_counter*100),end="")
        print("%")
        print("  PID Reset Rate Attacks \t: ",end="")
        print("%5s" % attack_stat[2],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[2])/total_counter*100),end="")
        print("%")
        print("  PID Rate Attacks \t\t: ",end="")
        print("%5s" % attack_stat[3],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[3])/total_counter*100),end="")
        print("%")
        print("  PID Deadband Attacks \t\t: ",end="")
        print("%5s" % attack_stat[4],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[4])/total_counter*100),end="")
        print("%")
        print("  PID Cycle Time Attacks \t: ",end="")
        print("%5s" % attack_stat[5],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[5])/total_counter*100),end="")
        print("%")
        print("  Pump Attack \t\t\t: ",end="")
        print("%5s" % attack_stat[6],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[6])/total_counter*100),end="")
        print("%")
        print("  Solenoid Attack \t\t: ",end="")
        print("%5s" % attack_stat[7],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[7])/total_counter*100),end="")
        print("%")
        print("  System Mode Attack \t\t: ",end="")
        print("%5s" % attack_stat[8],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[8])/total_counter*100),end="")
        print("%")
        print("  Critical Condition Attacks \t: ",end="")
        print("%5s" % attack_stat[9],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[9])/total_counter*100),end="")
        print("%")
        print("  Bad CRC Attack \t\t: ",end="")
        print("%5s" % attack_stat[10],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[10])/total_counter*100),end="")
        print("%")
        print("  Clean Registers Attack \t: ",end="")
        print("%5s" % attack_stat[11],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[11])/total_counter*100),end="")
        print("%")
        print("  Device Scan Attack \t\t: ",end="")
        print("%5s" % attack_stat[12],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[12])/total_counter*100),end="")
        print("%")
        print("  Force Listen Attack \t\t: ",end="")
        print("%5s" % attack_stat[13],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[13])/total_counter*100),end="")
        print("%")
        print("  Restart Attack \t\t: ",end="")
        print("%5s" % attack_stat[14],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[14])/total_counter*100),end="")
        print("%")
        print("  Read Id Attack \t\t: ",end="")
        print("%5s" % attack_stat[15],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[15])/total_counter*100),end="")
        print("%")
        print("  Function Code Scan Attack \t: ",end="")
        print("%5s" % attack_stat[16],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[16])/total_counter*100),end="")
        print("%")
        print("  Rise/Fall Attacks \t\t: ",end="")
        print("%5s" % attack_stat[17],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[17])/total_counter*100),end="")
        print("%")
        print("  Slope Attacks \t\t: ",end="")
        print("%5s" % attack_stat[18],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[18])/total_counter*100),end="")
        print("%")
        print("  Random Value Attacks \t\t: ",end="")
        print("%5s" % attack_stat[19],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[19])/total_counter*100),end="")
        print("%")
        print("  Negative Pressure Attack \t: ",end="")
        print("%5s" % attack_stat[20],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[20])/total_counter*100),end="")
        print("%")
        print("  Fast Attacks \t\t\t: ",end="")
        print("%5s" % attack_stat[21],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[21])/total_counter*100),end="")
        print("%")
        print("  Slow Attack \t\t\t: ",end="")
        print("%5s" % attack_stat[22],end="")
        print("\t",end="")
        print("%.2f " % (float(attack_stat[22])/total_counter*100),end="")
        print("%")
        print("---------------------------------------------------------")
        print("  Total Number of Attacks \t: ",end="")
        print("%5s" % sum(attack_stat.values()))
        print("---------------------------------------------------------")
        print("---------------------------------------------------------")
        print("  Total MODBUS Packets \t\t: ",end="")
        print("%5s" % total_counter)
        print("---------------------------------------------------------")


## process the data packet
def processor(data):
        if check_attack(data.spc_rslt):
                statistics(data.spc_rslt)
                printer(data)

def main():
        try:
                with open (sys.argv[1], "r") as fp:
                        ## reading the arff header
                        for line in fp:
                                ## ignoring the comments section
                                if line.startswith("%"):
                                        continue
                                ## moving to the data section
                                if line.startswith("@data"):
                                        break
                                ## skipping the attributes
                                if line.startswith("@"):
                                        continue
                        ## reading the data
                        for line in fp:
                                data = ARFF(line.strip())
                                global total_counter
                                total_counter = total_counter + 1 
                                processor(data)
                statistic_printer()
        except KeyboardInterrupt:
                statistic_printer()
                sys.exit()

if __name__ == '__main__':
        main()
