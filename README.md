# EML-Parser

This Python script reads an `.eml` file and extracts various headers and information, including hash values, sender and recipient details, sanitized IP addresses, and URLs. It can also convert HTML content to plain text and supports outputting results to the console or a file.

## Features

- Calculate and display:
  - MD5, SHA1, and SHA256 hashes of the `.eml` file.
- Extract and display:
  - `From`, `To`, `Subject`, `Date`, `CC`, and `BCC` headers.
  - List of attachments.
  - Unique IP addresses and URLs from the email body.
  - HTML embedded content as plain text.
  - `X-*` headers.
- Sanitize IP addresses by replacing `.` with `[.]`.
- Options to copy output to the clipboard (console only) or save to a specified file.

## Requirements

- Python 3.x

## Usage

1. Save the script as `script.py`.
2. Open your terminal or command prompt.
3. Navigate to the directory where the script is saved.
4. Run the script with the following command:

   ```bash
   python script.py <eml_file> [-c | -f <output_file> | -fs <output_file>]
   ```
## Options

- `<eml_file>`: The path to the `.eml` file you want to process.
- `-c`: Copy the output to the clipboard (not implemented in this version).
- `-f <output_file>`: Save the output to the specified file.
- `-fs <output_file>`: Save the output to the specified file and sanitize IP addresses.

## Example Commands

To output to the console:

```bash
python script.py example.eml
```

To save the output to a file:


```bash
python script.py example.eml -f output.txt
```

To sanitize IP addresses and save to a file:


```bash
python script.py example.eml -fs output.txt

```

