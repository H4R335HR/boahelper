# boasquash

Helper script for logging into certian routers with Boa httpd

## Description

Run the script with proper arguments and you can open the router's admin page in any web browser to find yourself logged in.

## Usage

### Prerequisites

- Python 3.x
- `requests` library (install using `pip install requests`)

### Command-line Arguments

- `-u`, `--username`: Specify the username (optional).
- `-p`, `--password`: Specify the password (optional).
- `-H`, `--host`: Specify the host (optional).

### Running the Script

Example usage:

```bash
python boasquash.py -u <username> -p <password> -H <host>

