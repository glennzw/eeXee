# eeXee

Utility to extract Portable Executable (PE) file properties from all files in a given directory. Extracted fields include: 
 * Filename
 * Folder
 * CompanyName
 * FileDescription
 * FileVersion
 * InternalName
 * LegalCopyright
 * OriginalFilename
 * ProductName
 * Icon

The icon is saved in a Base64 format embedded in the output file.


Usage: eeXee.py [-h] [-r] [-o {csv,json,html,all}] [-f FILE] directory

positional arguments:
  directory             Directory to search for .exe files

optional arguments:
  -h, --help            show this help message and exit
  -r, --recursive       Recursively search through subdirectories
  -o {csv,json,html,all}, --output {csv,json,html,all}
                        Output format (csv, json, html, or all)
  -f FILE, --file FILE  Output file name without extension

