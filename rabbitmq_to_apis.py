import subprocess
import threading
import time
import json
import requests
import pika  
import base64
import pandas as pd
from io import BytesIO
import httpx
import os
import asyncio
from feature_processing import process_file
import threading
from packet_analyzer import *
import gzip
import shutil
import datetime
import base64
from functools import reduce

# Configuration
RABBITMQ_URL = "amqp://guest:guest@rabbitmq:5672"  # Default port for RabbitMQ is 5672
QUEUE_NAME = "testQueue"
API_NB15 = "http://192.168.100.91:8002/predict-all"
API_BACKEND = "http://192.168.100.4:3000/data"
FILENAME = ""
OS = ""
ARCH = ""
HOSTNAME = ""
SERVERID = ""

def run_preprocessing(script_name, filename):
    """Runs a preprocessing script with the provided data."""
    rs=subprocess.run([f"./{script_name}", f"{filename}"])  # Run the script
    

def decompress_file(input_filename, output_filename):
    try:
        with gzip.open(input_filename, 'rb') as f_in:
            with open(output_filename, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        print(f"File decompressed successfully to {output_filename}")
    except Exception as e:
        print(f"Error while decompressing file: {e}")


def convert_to_parquet(filename):
    df= pd.read_csv(filename)
    new_file = filename.split(".csv")[0]+".parquet"

    with open(new_file, "wb") as f:
        df.to_parquet(f)

    return new_file

def process_pcap_files():
    global FILENAME, OS, ARCH, HOSTNAME, SERVERID
    print("thread2 filename", FILENAME)
    analyzer= PcapAnalyzer(FILENAME, OS, ARCH, HOSTNAME, SERVERID)
    asyncio.run(analyzer.send_to_elastic())

async def threat_res(data, df):
    flattened_data = [item for sublist in data for item in sublist]
    benign = len(data)-len(flattened_data) 
    if ((benign / len(data))*100)>=50:
         print("SAFE")
         return 
    # Count the occurrences of each category
    category_counts = Counter(flattened_data)
    print(category_counts)
    most_common_category = category_counts.most_common(1)[0]
    print(most_common_category)
    if most_common_category[1] > benign:
         print("THE SYSTEM DETECTED A THREAT: " , most_common_category[0])
         index_of_exploits = reduce(lambda acc, elem: acc if acc != -1 else data.index(elem) if most_common_category[0] in elem else acc,data,-1)
         message={"threat": most_common_category[0], "threat_data": df.iloc[index_of_exploits].to_dict()}
         message["annotation"]= most_common_category[0]
         response= requests.post(API_BACKEND, json=message)
              
    else:
         print("NO THREAT WAS DETECTED")


async def process_message(message):
    """Processes a single message by sending a file to the API."""

    global FILENAME, OS, ARCH, HOSTNAME, SERVERID
    
    #ndle new PCAP file
    id_srv= message.get('device_id')
    SERVERID = id_srv   
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    filename= message.get('filename')

    FILENAME = filename
    OS = message.get("os")
    ARCH = message.get("arch")
    HOSTNAME = message.get("hostname")

    file_data = base64.b64decode(message.get('file_data'))
    try:
        # Decompress the data (assuming gzip compression)
        with open(filename, 'wb') as f:
            f.write(file_data)

        print(f"Processed file with ID: {id_srv}")
        
        
    except Exception as e:
        print(f"Failed to process message: {e}")

    # Start Extraction
    
    print("=================> Start Extraction")
    run_preprocessing("process_pcap.sh", filename)
    thread = threading.Thread(target = process_pcap_files)
    thread.start()
    print("Processing done!")
    res_filename = 'FinalOutput/MERGED_'+filename.split(".pcap")[0]+'.csv'
    print("Results in ", res_filename)
    
    print("=================> Process Results")
    process_file(res_filename)

    # Wait for the output file
    data_rec = pd.read_csv(res_filename)
    filename = convert_to_parquet(res_filename)
    
    print("=================> Pass Data to Model Pipeline")
    with open(filename, "rb") as file:
        parquet_buffer = BytesIO(file.read())
    
    async with httpx.AsyncClient() as client:
        files = {'file': (filename, parquet_buffer, "application/octet-stream") }
        response = await client.post(API_NB15, files=files)

    print(response.text)
    df = pd.read_csv(res_filename)
    
    print("=================> Analyze Results")
    payload = json.loads(response.text)
    await threat_res(payload, df)
    
    thread.join()
    return "ITERATION DONE"



async def consume_messages():
    """Consumes messages from RabbitMQ asynchronously and processes them."""
    # Establish a connection using pika
    print('Waiting for messages. To exit press CTRL+C')

    connection = pika.BlockingConnection(pika.ConnectionParameters(host='rabbitmq'))
    channel = connection.channel()

    # Declare the queue (ensure it exists)
    channel.queue_declare(queue=QUEUE_NAME, durable= True)
    
    # Consume messages from the queue
    async def callback(ch, method, properties, body):
        
        message={"device_id": properties.headers["device_id"],"os": properties.headers["os"], "hostname": properties.headers["hostname"], "arch": properties.headers["arch"] , "file_data": body, "filename": properties.headers["filename"]}
        
        res_nb15 = await process_message(message)
        print(res_nb15)
        ch.basic_ack(delivery_tag=method.delivery_tag)
    # Start consuming messages
    for method_frame, properties, body in channel.consume(queue=QUEUE_NAME, auto_ack=False):
        if method_frame:
                time.sleep(0.1)
                await callback(channel, method_frame, properties, body)



def main():

    # Start consuming messages
    asyncio.run(consume_messages())


if __name__ == "__main__":
    main()
