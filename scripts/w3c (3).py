import datetime as dt
import csv
import airflow
import requests
import os
from datetime import datetime
import requests.exceptions as requests_exceptions
from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator
import requests
import json
import mysql.connector
import logging

BaseDir="/home/airflow/gcs/data"
RawFiles=BaseDir+"/Raw/"
Staging=BaseDir+"/Staging/"
StarSchema=BaseDir+"/StarSchema/"
# DimIP = open(Staging+'DimIP.txt', 'r')
# DimUnicIP=open(Staging+'DimIPUniq.txt', 'w')
# uniqCommand="sort "+Staging+"DimIP.txt | uniq > "+Staging+'DimIPUniq.txt'

uniqCommand="sort -u "+Staging+"DimIP.txt > "+Staging+'DimIPUniq.txt'
uniqDateCommand="sort -u "+Staging+"DimDate.txt > "+Staging+'DimDateUniq.txt'

# uniqCommand="sort -u -o "+Staging+"DimIPUniq.txt " +Staging+"DimIP.txt"
# 2>"+Staging+"errors.txt"
try:
   os.mkdir(BaseDir)
except:
   print("Can't make BaseDir")
try:
   os.mkdir(RawFiles)
except:
   print("Can't make BaseDir")
try:
   os.mkdir(Staging)
except:
   print("Can't make BaseDir")
try:
   os.mkdir(StarSchema)
except:
   print("Can't make BaseDir")


def CleanHash(filename):
    print('Cleaning ',filename)
    logging.warning('Cleaning '+filename)
    print (uniqCommand)
    type=filename[-3:len(filename)]
    if (type=="log"):

        OutputFileShort=open(Staging+'Outputshort.txt', 'a')
        OutputFileLong=open(Staging+'Outputlong.txt', 'a')

        InFile = open(RawFiles+filename,'r')

        Lines= InFile.readlines()
        for line in Lines:
            if (line[0]!="#"):
                Split=line.split(" ")

                if (len(Split)==14):

                   OutputFileShort.write(line)
#                    print('Short ',filename,len(Split))
                else:
                   if (len(Split)==18):
                       OutputFileLong.write(line)
#                        print('Long ',filename,len(Split))
                   else:
                       print ("Fault "+str(len(Split)))

def DeleteFiles():
    OutputFileShort=open(Staging+'Outputshort.txt', 'w')
    OutputFileLong=open(Staging+'Outputlong.txt', 'w')

def ListFiles():

   arr=os.listdir(RawFiles)

   if not arr:
      print('List arr is empty')

# Output:
# 'List is empty'

   logging.warning('Starting List Files' +",".join(str(element) for element in arr))
   DeleteFiles()
   for f in arr:
       logging.warning('calling Clean '+f)
       CleanHash(f)

def BuildFactShort():
    InFile = open(Staging+'Outputshort.txt','r')
    OutFact1=open(Staging+'OutFact1.txt', 'a')

    Lines= InFile.readlines()
    for line in Lines:
        Split=line.split(" ")
        Browser=Split[9].replace(",","")
        Out=Split[0]+","+Split[1]+","+Browser+","+Split[8]+","+Split[13]

        OutFact1.write(Out)

def BuildFactLong():
    InFile = open(Staging+'Outputlong.txt','r')
    OutFact1=open(Staging+'OutFact1.txt', 'a')

    Lines= InFile.readlines()
    for line in Lines:
        Split=line.split(" ")
        Browser=Split[9].replace(",","")
        Out=Split[0]+","+Split[1]+","+Browser+","+Split[8]+","+Split[16]
        OutFact1.write(Out)

def Fact1():
    with open(Staging+'OutFact1.txt', 'w') as file:
        file.write("Date,Time,Browser,IP,ResponseTime\n")
    BuildFactShort()
    BuildFactLong()

def getIPs():
    InFile = open(Staging+'OutFact1.txt', 'r')
    OutputFile=open(Staging+'DimIP.txt', 'w')
    Lines= InFile.readlines()
    for line in Lines:
        Split=line.split(",")
        Out=Split[3]+"\n"
        OutputFile.write(Out)
def makeDimDate():
    InFile = open(Staging+'OutFact1.txt', 'r')
    OutputFile=open(Staging+'DimDate.txt', 'w')

    Lines= InFile.readlines()
    for line in Lines:
        Split=line.split(",")
        Out=Split[0]+"\n"
        OutputFile.write(Out)

Days=["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]


def getDates():
    InDateFile = open(Staging+'DimDateUniq.txt', 'r')
    OutputDateFile=open(StarSchema+'DimDateTable.txt', 'w')
    with OutputDateFile as file:
       file.write("Date,Year,Month,Day,DayofWeek\n")
    Lines= InDateFile.readlines()

    for line in Lines:
        line=line.replace("\n","")
        print(line)
        try:
            date=datetime.strptime(line,"%Y-%m-%d").date()
            weekday=Days[date.weekday()]
            out=str(date)+","+str(date.year)+","+str(date.month)+","+str(date.day)+","+weekday+"\n"

            with open(StarSchema+'DimDateTable.txt', 'a') as file:
               file.write(out)
        except:
            print("Error with Date")

def GetLocations():
    DimTablename=StarSchema+'DimIPLoc.txt'
    try:
        file_stats = os.stat(DimTablename)

        if (file_stats.st_size >2):
           print("Dim IP Table Exists")
           return
    except:
        print("Dim Table IP does not exist, creating one")
    InFile=open(Staging+'DimIPUniq.txt', 'r')
    OutFile=open(StarSchema+'DimIPLoc.txt', 'w')


    Lines= InFile.readlines()
    for line in Lines:
        line=line.replace("\n","")
        # URL to send the request to
        request_url = 'https://geolocation-db.com/jsonp/' + line
#         print (request_url)
        # Send request and decode the result
        try:
            response = requests.get(request_url)
            result = response.content.decode()
        except:
            print ("error reponse"+result)
        try:
        # Clean the returned string so it just contains the dictionary data for the IP address
            result = result.split("(")[1].strip(")")
        # Convert this data into a dictionary
            result  = json.loads(result)
            out=line+","+str(result["country_code"])+","+str(result["country_name"])+","+str(result["city"])+","+str(result["latitude"])+","+str(result["longitude"])+"\n"
#            print(out)
            with open(StarSchema+'DimIPLoc.txt', 'a') as file:
               file.write(out)
        except:
            print ("error getting location")

dag = DAG(
   dag_id="Process_W3_Data",
   schedule_interval="@daily",
   start_date=dt.datetime(2023, 2, 24),
   catchup=False,
)
download_data = PythonOperator(
   task_id="RemoveHash",
   python_callable=ListFiles,
   dag=dag,
)

DimIp = PythonOperator(
    task_id="DimIP",
    python_callable=getIPs,
    dag=dag,
)

DateTable = PythonOperator(
    task_id="DateTable",
    python_callable=makeDimDate,
    dag=dag,
)

IPTable = PythonOperator(
    task_id="IPTable",
    python_callable=GetLocations,
    dag=dag,
)

BuildFact1 = PythonOperator(
   task_id="BuildFact1",
   python_callable= Fact1,
   dag=dag,
)

BuildDimDate = PythonOperator(
   task_id="BuildDimDate",
   python_callable=getDates,
   dag=dag,
)

uniq = BashOperator(
    task_id="uniqIP",
    bash_command=uniqCommand,
#     bash_command="echo 'hello' > /home/airflow/gcs/Staging/hello.txt",

    dag=dag,
)

uniq2 = BashOperator(
    task_id="uniqDate",
    bash_command=uniqDateCommand,
#     bash_command="echo 'hello' > /home/airflow/gcs/Staging/hello.txt",

    dag=dag,
)

copyfact = BashOperator(
    task_id="copyfact",
#    bash_command=uniqDateCommand,
     bash_command="cp /home/airflow/gcs/data/Staging/OutFact1.txt /home/airflow/gcs/data/StarSchema/OutFact1.txt",

    dag=dag,
)


# download_data >> BuildFact1 >>DimIp>>DateTable>>uniq>>uniq2>>BuildDimDate>>IPTable

BuildFact1.set_upstream(task_or_task_list=[download_data])
DimIp.set_upstream(task_or_task_list=[BuildFact1])
DateTable.set_upstream(task_or_task_list=[BuildFact1])
uniq2.set_upstream(task_or_task_list=[DateTable])
uniq.set_upstream(task_or_task_list=[DimIp])
BuildDimDate.set_upstream(task_or_task_list=[uniq2])
IPTable.set_upstream(task_or_task_list=[uniq])
copyfact.set_upstream(task_or_task_list=[IPTable,BuildDimDate])

