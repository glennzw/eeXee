#!/usr/bin/env python
"""\
Author: Glenn Wilkinson // glennzw@protonmail.com
Utility to extract Portable Executable (PE) file properties

Usage: eeXee.py [-h] [-r] [-o {csv,json,html,all}] [-f FILE] directory

positional arguments:
  directory             Directory to search for .exe files

optional arguments:
  -h, --help            show this help message and exit
  -r, --recursive       Recursively search through subdirectories
  -o {csv,json,html,all}, --output {csv,json,html,all}
                        Output format (csv, json, html, or all)
  -f FILE, --file FILE  Output file name without extension
"""

import argparse
import os
import pefile
import base64
import json
import csv
import subprocess
import time
#from jinja2 import Environment, FileSystemLoader # From file
from jinja2 import Environment, DictLoader # From a variable
import logging
from logging import FileHandler
import sys

template_html = '''
<!DOCTYPE html><html lang="en"><head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Exe File Information</title> <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.5.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KyZXEAg3QhqLMpG8r+Knujsl7/1rxz8l/7f0PYz35u2z8l/3f5c1K3AerFgmtwn9" crossorigin="anonymous"> <style> body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; } th, td { border: 1px solid #dee2e6; } </style></head><body> <div class="container"> <h1 class="my-4">Exe File Information</h1> <table class="table"> <thead class="table-light"> <tr> <th scope="col">Icon</th> <th scope="col">Filename</th> <th scope="col">Folder</th> <th scope="col">CompanyName</th> <th scope="col">FileDescription</th> <th scope="col">FileVersion</th> <th scope="col">InternalName</th> <th scope="col">LegalCopyright</th> <th scope="col">OriginalFilename</th> <th scope="col">ProductName</th> </tr> </thead> <tbody> {% for item in data %} <tr> <td><img src="data:image/png;base64,{{ item.Icon }}" alt="{{ item.Filename }}" width="32" height="32"></td> <td>{{ item.Filename }}</td> <td>{{ item.Folder }}</td> <td>{{ item.CompanyName }}</td> <td>{{ item.FileDescription }}</td> <td>{{ item.FileVersion }}</td> <td>{{ item.InternalName }}</td> <td>{{ item.LegalCopyright }}</td> <td>{{ item.OriginalFilename }}</td> <td>{{ item.ProductName }}</td> </tr> {% endfor %} </tbody> </table> </div> <!-- Add Bootstrap 5 JavaScript --> <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.7/dist/umd/popper.min.js" integrity="sha384-7/zpzZRak8U+7Kw1TIq0v8FqFjcJ6pajs/rfdfs3SO+kD4Ck5BdPtF+to8xMp9U4" crossorigin="anonymous"></script> <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.5.0-alpha1/dist/js/bootstrap.min.js" integrity="sha384-cn7l7gDp0eyniUwwAZgrzD06kc/tftFf19TOAs2zVinnD/C7E91j9yyk5//jjpt/" crossorigin="anonymous"></script></body></html>
'''

def setup_logger():
    logger = logging.getLogger('custom_logger')
    logger.setLevel(logging.ERROR)

    file_handler = FileHandler('error_log.txt')
    file_handler.setLevel(logging.ERROR)

    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.propagate = False

    return logger

logger = setup_logger()


def find_files(path, recursive, extension):
    if recursive:
        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(extension):
                    yield os.path.join(root, file)
    else:
        for file in os.listdir(path):
            if file.endswith(extension):
                yield os.path.join(path, file)

def get_pe_properties(file_path):
    pe = pefile.PE(file_path)

    properties = {}
    for file_info in pe.FileInfo:
        for entry in file_info:
            if entry.Key == b'StringFileInfo':
                for st in entry.StringTable:
                    for key, value in st.entries.items():
                        properties[key.decode()] = value.decode()
            elif entry.Key == b'VarFileInfo':
                for var in entry.Var:
                    key, value = list(var.entry.items())[0]
                    properties[key.decode()] = value

    return properties

def get_icon_base64(file_path):
    ps_command = f"""
    Add-Type -AssemblyName System.Drawing;
    $ErrorActionPreference = 'Stop';
    $filePath = '{file_path}' | ConvertTo-Json | ConvertFrom-Json
    $base64Image = [Convert]::ToBase64String((($ms = New-Object System.IO.MemoryStream), ([System.Drawing.Icon]::ExtractAssociatedIcon($filePath)).ToBitmap().Save($ms, [System.Drawing.Imaging.ImageFormat]::Bmp), ($ms.Position = 0), $ms.ToArray())[-1]);
    $base64Image
    """
    result = subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_command], capture_output=True, text=True, check=True)
    return result.stdout.strip()

def print_progress_bar(iteration, total, elapsed_time, prefix='', suffix='', decimals=1, length=100, fill='█', print_end="\r"):
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    eta = elapsed_time * (total - iteration) / iteration if iteration > 0 else 0
    eta_formatted = time.strftime("%H:%M:%S", time.gmtime(eta))
    print(f'\r{prefix} |{bar}| {percent}% {suffix} ETA: {eta_formatted}', end=print_end)
    if iteration == total:
        print()

def generate_html(data):
    # env = Environment(loader=FileSystemLoader('.'))   # Load from file
    templates = {'template.html': template_html}        # Load from variable
    env = Environment(loader=DictLoader(templates))     # Load from variable
    template = env.get_template('template.html')
    return template.render(data=data)

def main():
    parser = argparse.ArgumentParser(description="Gather information from .exe files")
    parser.add_argument("directory", help="Directory to search for .exe files")
    parser.add_argument("-r", "--recursive", action="store_true", help="Recursively search through subdirectories")
    parser.add_argument("-o", "--output", choices=["csv", "json", "html", "all"], default="all", help="Output format (csv, json, html, or all)")
    parser.add_argument("-f", "--file", default="output", help="Output file name without extension")
    args = parser.parse_args()

    exe_files = list(find_files(args.directory, args.recursive, ".exe"))#[:10]
    output_data = []

    print("[+] Searching for .exe files...")
    if len(exe_files) < 1:
        print("[!] No exe files found in given path. Exiting.")
        sys.exit(0)

    print("[+] Loaded up " + str(len(exe_files)) + " .exe files to parse")
    start_time = time.time()
    num_errors = 0

    for i, file_path in enumerate(exe_files, start=1):
        try:
            file_properties = get_pe_properties(file_path)
            icon_base64 = get_icon_base64(file_path)
            folder, filename = os.path.split(file_path)

            data = {
                "Fi": filename,
                "Folder": folder,
                "CompanyName": file_properties.get("CompanyName", ""),
                "FileDescription": file_properties.get("FileDescription", ""),
                "FileVersion": file_properties.get("FileVersion", ""),
                "InternalName": file_properties.get("InternalName", ""),
                "LegalCopyright": file_properties.get("LegalCopyright", ""),
                "OriginalFilename": file_properties.get("OriginalFilename", ""),
                "ProductName": file_properties.get("ProductName", ""),
                #"ProductVersion": file_properties.get("ProductVersion", ""),
                #"Debug": file_properties.get("Debug", ""),
                #"Patched": file_properties.get("Patched", ""),
                #"PreRelease": file_properties.get("PreRelease", ""),
                #"PrivateBuild": file_properties.get("PrivateBuild", ""),
                #"SpecialBuild": file_properties.get("SpecialBuild", ""),
                #"Language": file_properties.get("Language", ""),
                "Icon": icon_base64
            }

            output_data.append(data)
        except Exception as e:
            logger.error(f"An error occurred parsing: {file_path}")
            logger.error(f"Error details: {e}")
            num_errors += 1
        #finally:    
        elapsed_time = time.time() - start_time
        print_progress_bar(i, len(exe_files), elapsed_time, prefix='Progress:', suffix='Complete', length=50)

    if num_errors > 0:
        print("Finished. Failed to parse " + str(num_errors) + " exe files. Please see error_log.txt")
    else:
        print("Finished.")

    if args.output in ("json", "all"):
        with open(f"{args.file}.json", "w") as json_file:
            json.dump(output_data, json_file, indent=4)
    if args.output in ("html", "all"):
        html_content = generate_html(output_data)
        with open(f"{args.file}.html", "w", encoding="utf-8") as html_file:
            html_file.write(html_content)
    if args.output in ("csv", "all"):
        keys = output_data[0].keys()
        with open(f"{args.file}.csv", "w", newline="") as csv_file:
            dict_writer = csv.DictWriter(csv_file, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(output_data)

if __name__ == "__main__":
   main()
